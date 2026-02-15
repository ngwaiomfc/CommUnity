import pysimpleGUI as sg

layout = [[sg.Text("Hello")]
          [sg.Button("ok")]]

window = sg.Window("CommUnity", layout)
while True:
    event, Values = window.read()
    if event == sg.WIN_CLOSED or event == "OK":
        break

window.close()
