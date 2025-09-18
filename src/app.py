from flask import Flask, request
import logging

app = Flask(__name__)

# Enable logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def hello_world():
    app.logger.info("Received request to /")
    response = 'Hello, World : ) This application is running inside the hardened container.'
    app.logger.info(f"Sending response: {response}")
    return response

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
