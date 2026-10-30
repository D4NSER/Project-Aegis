"""A scanner report must not unlock controls before the restore worker finishes."""
import queue
import unittest
from types import SimpleNamespace
from vm_control_ui import VMControlWindow


class Value:
    def __init__(self):self.value=None
    def set(self,value):self.value=value


class Output:
    def configure(self,**kwargs):pass
    def insert(self,*args):pass
    def see(self,*args):pass


class Window:
    def after(self,*args):pass


class VMControlUITests(unittest.TestCase):
    def test_transfer_report_keeps_actions_locked_until_restore_finishes(self):
        ui=VMControlWindow.__new__(VMControlWindow)
        ui.events=queue.Queue();ui.busy=True;ui.status=Value();ui.output=Output();ui.window=Window();ui.manager=None
        unlocked=[];ui.render_buttons=lambda:unlocked.append(True)
        ui.events.put(('transfer_restoring',{}))
        ui.poll()
        self.assertTrue(ui.busy);self.assertEqual([],unlocked)
        self.assertIn('atkuriama',ui.status.value)
        ui.events.put(('done',{'state':'restored','vm_restore_verified':True}))
        ui.poll()
        self.assertFalse(ui.busy);self.assertEqual([True],unlocked)

    def test_environment_refresh_revokes_previously_available_scan_actions(self):
        class Button:
            def __init__(self):self.state='normal'
            def configure(self,**options):self.state=options['state']
        ui=VMControlWindow.__new__(VMControlWindow)
        names=('check_button','cycle_button','restore_button','boot_button','scan_button',
               'scan_finish','scan_defer','lab_prepare','lab_finish','lab_defer','lab_start','transfer_button')
        for name in names:setattr(ui,name,Button())
        ui.awaiting_connect=False
        ui.config={'yara_executable':'configured','procmon_vendor_root':'configured','collection_root':'configured'}
        ui.manager=SimpleNamespace(session=SimpleNamespace(state='restored'),
            environment={'personal_accounts_separated':True,'network_up':False},
            connection=SimpleNamespace(pending=False),pending_scan=None,scanner_cleanup=None,lab=SimpleNamespace(pending=None))
        ui.render_buttons()
        self.assertEqual('normal',ui.scan_button.state)
        ui.manager.environment['network_up']=True
        ui.render_buttons()
        for name in ('cycle_button','scan_button','lab_prepare','transfer_button'):
            self.assertEqual('disabled',getattr(ui,name).state,name)

    def test_intermediate_scanner_result_keeps_all_actions_locked_during_restore(self):
        ui=VMControlWindow.__new__(VMControlWindow)
        ui.events=queue.Queue();ui.busy=True;ui.status=Value();ui.output=Output();ui.window=Window();ui.manager=None
        unlocked=[];ui.render_buttons=lambda:unlocked.append(True)
        report={'yara_version':'4.6.0','files':[{'yara_status':'MATCHED','yara_expected_match':True,'av_status':'NOT_DETECTED'}]}
        ui.events.put(('scanner_restoring',{'report':report}))
        ui.poll()
        self.assertTrue(ui.busy);self.assertEqual([],unlocked)
        ui.events.put(('error','fixture restore failure'))
        ui.poll()
        self.assertFalse(ui.busy);self.assertEqual([True],unlocked)
        self.assertIn('nebaigtas',ui.status.value)


if __name__=='__main__':unittest.main()
