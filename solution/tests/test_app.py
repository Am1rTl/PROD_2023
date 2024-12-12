import requests
import json

BASE_URL = "http://localhost:8080"  # Adjust the base URL if needed

def test_sign_in():
    response = requests.post(f"{BASE_URL}/api/auth/sign-in", json={"login": "testuser", "password": "testpass"})
    assert response.status_code == 200
    assert "token" in response.json()

def test_sign_in_missing_fields():
    response = requests.post(f"{BASE_URL}/api/auth/sign-in", json={"login": "testuser"})
    assert response.status_code == 400
    assert response.json()["reason"] == "Login and password are required"

def test_register_user():
    response = requests.post(f"{BASE_URL}/api/auth/register", json={
        "login": "testuser",
        "email": "testuser@example.com",
        "password": "testpass",
        "countryCode": "US",
        "isPublic": True
    })
    assert response.status_code == 201
    assert response.json()["message"] == "User registered successfully"

def test_register_user_missing_fields():
    response = requests.post(f"{BASE_URL}/api/auth/register", json={"login": "newuser"})
    assert response.status_code == 400
    assert "Missing fields" in response.json()["reason"]

def test_register_user_with_existing_login():
    # First, register a user
    requests.post(f"{BASE_URL}/api/auth/register", json={
        "login": "existinguser",
        "email": "existinguser@example.com",
        "password": "testpass",
        "countryCode": "US",
        "isPublic": True
    })
    
    # Attempt to register the same user again
    response = requests.post(f"{BASE_URL}/api/auth/register", json={
        "login": "existinguser",
        "email": "newemail@example.com",
        "password": "testpass",
        "countryCode": "US",
        "isPublic": True
    })
    assert response.status_code == 409
    assert response.json()["reason"] == "User  with this login, email, or phone already exists"

def test_get_countries():
    response = requests.get(f"{BASE_URL}/api/countries")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_country_by_alpha2():
    response = requests.get(f"{BASE_URL}/api/countries/US")
    assert response.status_code == 200
    assert response.json()["alpha2"] == "US"

def test_get_country_by_alpha2_not_found():
    response = requests.get(f"{BASE_URL}/api/countries/ZZ")
    assert response.status_code == 404
    assert response.json()["reason"] == "Invalid region"

def test_get_countries_invalid_region():
    response = requests.get(f"{BASE_URL}/api/countries?region=invalidregion")
    assert response.status_code == 400
    assert response.json()["reason"] == "Invalid region"

def test_get_countries_no_region():
    response = requests.get(f"{BASE_URL}/api/countries")
    assert response.status_code == 200
    assert isinstance(response.json(), list)  # Ensure it returns a list of countries

def test_ping():
    response = requests.get(f"{BASE_URL}/api/ping")
    assert response.status_code == 200
    assert response.text == "ok"

if __name__ == "__main__":
    test_register_user()
    test_register_user_missing_fields()
    test_sign_in()
    test_sign_in_missing_fields()
    test_get_countries()
    test_get_country_by_alpha2()
    test_get_country_by_alpha2_not_found()
    test_get_countries_invalid_region()
    test_get_countries_no_region()
    test_ping()
    print("Все тесты пройдены!")
