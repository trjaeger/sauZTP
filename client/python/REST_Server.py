from flask import Flask, json
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hey, we have Flask in a Docker container!'

@app.route('/requestvoucher',methods=['GET', 'POST'])
def voucher():
    return json.jsonify({'Voucher': "dies ist ein Voucher"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
