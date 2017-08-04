"""
    A simple wrapper class for paramiko

    Depends on pycrypto
"""

import logging
import sys
import time

# TODO: remap these if necessary based on how my local machine behaves
# (as opposed to toolchain)
PARAMIKO_PATH = "/build/toolchain/noarch/paramiko-1.15.1/lib/python2.7/site-packages/"
ECDSA_PATH = "/build/toolchain/noarch/ecdsa-0.10/lib/python2.7/site-packages/"
sys.path.insert(0, PARAMIKO_PATH)
sys.path.insert(0, ECDSA_PATH)

import paramiko, ecdsa

# Get rid of all paramiko log output below warning.
logging.getLogger("paramiko").setLevel(logging.WARNING)

class SSH():
    """
        Simple SSH wrapper. Wraps paramiko and performs most tasks you would
        need to perform over SSH.
    """

    def __init__(self, ipaddr, user, password, timeout=60, keepalive=30, conn_retries=10, retry_wait=10):
        error = None
        logging.info('Entering simple_ssh wrapper with values: ipaddr: %s, user: %s, timeout: %s, keepalive: %s, retries: %s, retry_wait: %s',
                        ipaddr, user, timeout, keepalive, conn_retries, retry_wait )
        msg = "Simple SSH Wrapper(%s,%s)" % (ipaddr,user)
        # After a new process is created, this needs to
        # be called and paramiko doesn't do it itself.
        # See: https://github.com/newsapps/beeswithmachineguns/issues/17
        logging.info('Entering simple_ssh wrapper with values: ipaddr: %s, user: %s, timeout: %s, keepalive: %s, retries: %s, retry_wait: %s',
                        ipaddr, user, timeout, keepalive, conn_retries, retry_wait )
        for try_num in range(conn_retries):
            error = None
            try:
                self._ssh = paramiko.SSHClient()
                self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._ssh.connect (ipaddr, username=user, password=password)
                self.sftp = None
                break
            except Exception as error:
                logging.warning('Simple_ssh - Raising Error. %s (try: %s), error: %s. Sleeping for %s seconds',
                                msg, try_num + 1, error, retry_wait)
                time.sleep(retry_wait)
        if error:
            logging.error('Simple_ssh - Raising Error. %s: %s', msg, error)
            raise error

    def get_sftp(self):
        """
            Returns a paramiko sftp object.
        """
        if not self.sftp:
            self.sftp = self._ssh.open_sftp()
        return self.sftp

    def close(self):
        """
            Closes the ssh and sftp connection
        """
        if self._ssh:
            self._ssh.close()

    def __del__(self):
        """
            "deconstructor" - runs the close method
        """
        try:
            self.close()
        except Exception:
            pass

    def cmd(self, cmd):
        """
            Exec a command a returns a tuple of stdout, stderr
            stdout, stderr will be strings
            if return_exit is True, there will be a third element in the tuple
            containing the command's exit code as an int.
        """
        chan = self._ssh.get_transport().open_session()
        chan.exec_command(cmd)
        chan.shutdown_write()
        # These will be lists of strings of any length. We receive as much data
        # as possible during every iteration of the loop, and append the data
        # to these lists so we don't need to do the expensive string copying
        # involved in string concatenation.
        stdout_buf = []
        stderr_buf = []
        while ((not chan.exit_status_ready()) or chan.recv_ready()
               or chan.recv_stderr_ready() or not chan.closed):
            if chan.recv_ready():
                avail = len(chan.in_buffer)
                stdout_buf.append(chan.recv(avail))
            if chan.recv_stderr_ready():
                avail = len(chan.in_stderr_buffer)
                stderr_buf.append(chan.recv_stderr(avail))
            time.sleep(.1)
            # Loop is done, we can now get the exit status and close the chan
        exit_status = chan.recv_exit_status()
        chan.close()
        # Turn the lists of partial strings into arrays
        stdout = ''.join(stdout_buf)
        stderr = ''.join(stderr_buf)
        return stdout, stderr, exit_status

    def switch_user_exec_cmd(self, password, cmd):
        """
            Switch to root user and execute a command
        """
        chan = self._ssh.invoke_shell()
        chan.send('su\n')
        buff = ''
        while not buff.endswith('Password: '):
            resp = chan.recv(9999)
            buff += resp

        chan.send(password)
        chan.send('\n')
        buff = ''
        while not buff.endswith('# '):
            resp = chan.recv(9999)
            buff += resp

        chan.send(cmd)
        chan.send('\n')
        buff = ''
        while not buff.endswith('# '):
            resp = chan.recv(9999)
            buff += resp

    def open_file(self, remote_path, mode):
        """
            Opens a remote file and returns a file-like object.
        """
        sftp = self.get_sftp()
        file_obj = sftp.open(remote_path, mode)
        file_obj.set_pipelined(True)
        return file_obj

    def copy_file(self, source_path, remote_path):
        """
            Copies a file from the source machine to the remote machine.
        """
        sftp = self.get_sftp()
        sftp.put(source_path, remote_path)

    def chmod(self, remote_path, mode):
        """
            Changes the permissions of a remote file
        """
        if type(mode) in (str, unicode):
            mode = int(mode, 8)
        self.get_sftp().chmod(remote_path, mode)
