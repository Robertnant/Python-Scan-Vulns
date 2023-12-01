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
from nmap_scanner import scanner
from database import check_vulnerabilities

def callback(input):
        print("Hello? "+input)
class BackGround(Widget):
    pass

class Screen(GridLayout):
    btn = ObjectProperty(None)

class Option_Selection(GridLayout):
    def ports_to_scan(self,value):
        self.ports = self.textinput.text
        self.porttext.text = "you are goin to scan the ports :"+self.textinput.text
    def Launch_App(self,value):
        if(self.sneakybutton.active):
            self.quickoptions = "1"
        if(self.politebutton.active):
            self.quickoptions = "2"
        if(self.aggbutton.active):
            self.quickoptions = "4"
        if(self.quickoptions == ""):
            self.quickoptions = "3"
        print(self.ports)
        print(self.quickoptions) 
        try:
            scanner(self.ports,self.quickoptions)
            L = check_vulnerabilities()
            s = '\n'.join(L)
            f = open("results.txt","w")
            f.write(s)
            f.close()
            os.system("python3.11 results.py")
        except:
            print("Check your arguments")
        else:
            print("Scan complete!")
        self.quickoptions = ""

    def __init__(self,**kwargs):
        super(Option_Selection, self).__init__(**kwargs)
        self.quickoptions = ""
        self.ports = ""
        self.cols = 4
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = "Choose your options and then proceed to a scan of your network!"))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = "Options:"))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = ""))

        self.add_widget(Label(text = "Sneaky"))
        self.sneakybutton = CheckBox(active = False,)# self.press_sneaky)
        self.add_widget(self.sneakybutton)
        self.add_widget(Label(text = ""))

        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = "Polite"))
        self.politebutton = CheckBox(active = False)#, self.press_polite)
        self.add_widget(self.politebutton)
        self.add_widget(Label(text = ""))

        self.add_widget(Label(text = ""))
        self.add_widget(Label(text = "Aggressive"))
        self.aggbutton = CheckBox(active = False)# self.press_agg)
        self.add_widget(self.aggbutton)
        self.add_widget(Label(text = ""))

        self.add_widget(Label(text = ""))
        self.textinput = TextInput(multiline = False,on_text_validate = self.ports_to_scan,size_hint_y = 0.1)
        self.add_widget(Label(text = "Ports you want to scan(22,80,443):"))
        self.add_widget(self.textinput)
        self.add_widget(Label(text = ""))

        self.add_widget(Label(text = ""))
        self.porttext = Label(text = "you are going to scan the ports :")
        self.add_widget(self.porttext)
        self.add_widget(Label(text = ""))
        self.btn = Button(text = "Scan!", on_press=self.Launch_App)
        self.add_widget(self.btn)

class Scannapp(App):
    def build(self):
        return Option_Selection()
    
if __name__ == "__main__":
    Scannapp().run()
