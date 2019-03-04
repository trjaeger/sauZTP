import requests

#resp = requests.get('https://todolist.example.com/tasks/')
url = 'http://172.20.0.2:5000/requestvoucher'
resp = requests.get(url)
#resp = requests.get('172.20.0.2:5000/')
if resp.status_code != 200:
    # This means something went wrong.
    raise
    #ApiError('GET / {}'.format(resp.status_code))
print(resp.json())
    #print('{} {}'.format(todo_item['id'], todo_item['summary']))

task = {"summary": "Take out trash", "description": "" }
resp2 = requests.post(url, json=task)

if resp2.status_code != 200:
    print('ERROR')
    #raise
    #('POST /tasks/ {}'.format(resp.status_code))
print(resp2.json())
