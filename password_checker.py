import PySimpleGUI as sg
import hashlib
import requests

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def check_password_security(password):
    count = pwned_api_check(password)
    if count:
        sg.popup(f'This password was found {count} times... you should probably change your password!')
    else:
        sg.popup('This password was NOT found. Carry on!')

def create_gui():
    layout = [
        [sg.Text('Enter your password:')],
        [sg.InputText(password_char='', key='-PASSWORD-')],
        [sg.Button('Check Password')],
    ]

    window = sg.Window('Password Security Check', layout)

    while True:
        event, values = window.read()

        if event == sg.WINDOW_CLOSED:
            break
        elif event == 'Check Password':
            check_password_security(values['-PASSWORD-'])

    window.close()

if __name__ == '__main__':
    create_gui()
