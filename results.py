import kivy
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen
from kivy.properties import ObjectProperty
from kivy.uix.widget import Widget
from kivy.uix.checkbox import CheckBox
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
import os

class Layout(GridLayout):
    def __init__(self):
        self.cols = 3
        f = open("results.txt")
        s = f.read()
        f.close()
        os.remove("results.txt")
        l = s.split('\n')
        self.add_widget(Label(text = "Results"))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
class ResultScreen(App):
    def build(self):
        return Layout()

if __name__ == "__main__":
    ResultScreen().run()