"""Actual native child entrypoint checks, with no release payload or USB access."""
import json
import os
import queue
import socket
import subprocess
import threading
import unittest


@unittest.skipUnless(os.environ.get('COUCH_NATIVE_HOST_TEST'), 'native executable required')
class NativeEntrypoint(unittest.TestCase):
    def start(self):
        """Run the real native host with only its private event channel."""
        executable=os.environ['COUCH_NATIVE_HOST_TEST']
        if os.name=='nt':
            process=subprocess.Popen([executable,'--events-stdio'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            return process,process.stdout,process.stdin,None
        parent,child=socket.socketpair()
        # fd3 must survive subprocess's descriptor cleanup too.
        process=subprocess.Popen([executable,'--events-fd','3'],pass_fds=tuple(set((3,child.fileno()))),preexec_fn=lambda:os.dup2(child.fileno(),3),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        child.close()
        stream=parent.makefile('rwb',buffering=0)
        return process,stream,stream,parent

    def drive(self,answer,timeout=15):
        """Answer prompts with `answer(prompt)` until the host finishes."""
        process,incoming,outgoing,parent=self.start()
        events=queue.Queue()
        def reader():
            try:
                while line:=incoming.readline():events.put(json.loads(line))
            finally:events.put(None)
        thread=threading.Thread(target=reader,daemon=True);thread.start()
        received=[]
        try:
            while True:
                value=events.get(timeout=timeout)
                if value is None:break
                received.append(value)
                if value['event']=='prompt':
                    outgoing.write(json.dumps({'id':value['id'],'value':answer(value)}).encode()+b'\n');outgoing.flush()
                if value['event']=='finished':break
            process.wait(timeout=timeout)
            return process.returncode,received
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            incoming.close()
            if outgoing is not incoming:outgoing.close()
            if parent is not None:parent.close()
            process.stderr.close()
            if process.stdout is not incoming:process.stdout.close()

    @staticmethod
    def labelled(prompt,*labels):
        """The value of the first offered option with one of these labels."""
        for label in labels:
            for option in prompt['options']:
                if option['label']==label:return option['value']
        raise AssertionError(f'{labels} not offered in {[o["label"] for o in prompt["options"]]}')

    def test_cancel_before_release_or_hardware_and_missing_config_is_visible(self):
        for cancel in (True,False):
            with self.subTest(cancel=cancel):
                answer=lambda prompt:self.labelled(prompt,'Cancel') if cancel else prompt['options'][0]['value']
                code,received=self.drive(answer)
                self.assertEqual(code,0 if cancel else 1)
                self.assertEqual(received[-1]['event'],'finished')
                if not cancel:self.assertTrue(any('release configuration' in v.get('detail','') for v in received))

    def test_leaving_recovery_reports_no_connected_remote_without_a_release(self):
        """The recovery action reaches its own device search with no config.

        Runners have no remote attached, so this exercises the real per-platform
        search - I/O Registry, sysfs or the Windows serial-port records - and
        must come back with the "nothing connected" screen rather than opening
        anything or asking for a release configuration.
        """
        code,received=self.drive(lambda prompt:self.labelled(prompt,'My remote shows COUCH RECOVERY','Find my remote','Stop'))
        self.assertEqual(code,0)
        self.assertEqual(received[-1]['event'],'finished')
        details=[v.get('detail','') for v in received]
        self.assertTrue(any('No remote in Couch recovery is connected' in d for d in details),details)
        self.assertFalse(any('release configuration' in d for d in details),details)
        # Nothing may be written or restarted on the way to that screen.
        self.assertFalse(any('mmcblk' in d or 'restart' in d.lower() for d in details),details)

if __name__=='__main__':unittest.main()
