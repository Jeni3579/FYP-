from app import create_app

app = create_app()

if __name__ == '__main__':
    print("--> Starting Hospital Staff server on http://127.0.0.1:8080/hospital")
    app.run(port=8080, debug=True, use_reloader=False)