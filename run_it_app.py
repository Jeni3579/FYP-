from app import create_app

app = create_app()

if __name__ == '__main__':
    print("--> Starting IT Staff server on http://127.0.0.1:5000/it")
    app.run(port=5000, debug=True, use_reloader=False)