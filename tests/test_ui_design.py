"""Custom buttons must preserve keyboard and disabled-action behavior."""
import unittest
from types import SimpleNamespace

from ui_design import Button


class ButtonFixture(Button):
    def __init__(self,command):
        self._command=command
        self._font=None
        self._enabled=True
        self._pressed=self._primary=self._selected=self._hover=False
        self.focused=False
    def focus_set(self):self.focused=True
    def _hover_to(self,value):self._hover=value
    def _draw(self):pass
    def _cancel(self):pass
    def winfo_width(self):return 120
    def winfo_height(self):return 44


class ButtonBehaviorTests(unittest.TestCase):
    def test_keyboard_repeat_and_disabled_transition_do_not_duplicate_an_action(self):
        calls=[];button=ButtonFixture(lambda:calls.append('action'))
        button._press(None);button._press(None)
        button._key_release(None);button._key_release(None)
        self.assertEqual(['action'],calls)
        self.assertTrue(button.focused)
        button._press(None)
        button.configure(state='disabled')
        button._key_release(None);button.invoke()
        self.assertEqual('disabled',button.cget('state'))
        self.assertEqual(['action'],calls)
        button.configure(state='normal')
        button._press(None);button._key_release(None)
        self.assertEqual(['action','action'],calls)

    def test_mouse_release_outside_or_after_leaving_cancels_the_action(self):
        calls=[];button=ButtonFixture(lambda:calls.append('action'))
        button._press(None);button._release(SimpleNamespace(x=140,y=22))
        button._press(None);button._leave(None);button._release(SimpleNamespace(x=40,y=22))
        self.assertEqual([],calls)
        button._press(None);button._release(SimpleNamespace(x=40,y=22))
        self.assertEqual(['action'],calls)


if __name__=='__main__':unittest.main()
