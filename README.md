
# Biskut Sweet Shop Management

<img width="1597" height="240" alt="image" src="https://github.com/user-attachments/assets/82f86307-2d08-4aa0-8dc5-ea3826917c79" />


## Project Overview
**Biskut Sweet Shop Management** is a web-based application developed using **Django** for backend and **HTML, CSS, JavaScript** for frontend. The system allows users to browse, search, and purchase sweets, while providing administrators full control to manage sweet inventory, including adding, updating, restocking, and deleting sweets. 

Key features include:
- Secure JWT user authentication and role-based access (Admin/User).
- Two factor Email Verification
- CRUD operations for sweets management.
- Inventory management with purchase and restock operations.
- Optional user profile information retrieval.
- Maintaining all activity logs


## Setup Instructions

Follow these steps to run the project locally:

1. **Clone the repository**
```bash
git clone <repository-url>
cd biskut-sweet-shop
````

2. **Create and activate virtual environment**

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Apply migrations**

```bash
python manage.py makemigrations
python manage.py migrate
```

5. **Create superuser (Admin)**

```bash
python manage.py createsuperuser
```

6. **Run the development server**

```bash
python manage.py runserver
```

7. Open your browser and go to:

```
http://127.0.0.1:8000/
```

---

## API Endpoints

### SWEETS API (Protected: Auth Required)

| Method | Endpoint           | Description                                | Access             |
| ------ | ------------------ | ------------------------------------------ | ------------------ |
| POST   | /api/sweets/       | Add a new sweet                            | Admin only         |
| GET    | /api/sweets/       | Get list of all sweets                     | Any logged-in user |
| GET    | /api/sweets/search | Search sweets by name/category/price range | Any logged-in user |
| PUT    | /api/sweets/<id>/  | Update sweet details                       | Admin only         |
| DELETE | /api/sweets/<id>/  | Delete a sweet                             | Admin only         |

### INVENTORY API (Protected)

| Method | Endpoint                  | Description                        | Access             |
| ------ | ------------------------- | ---------------------------------- | ------------------ |
| POST   | /api/sweets/<id>/purchase | Purchase sweet (decrease quantity) | Any logged-in user |
| POST   | /api/sweets/<id>/restock  | Restock sweet (increase quantity)  | Admin only         |

### Optional Utility API

| Method | Endpoint      | Description                      |
| ------ | ------------- | -------------------------------- |
| GET    | /api/users/me | Get profile info of current user |

---

## Postman Collection

You can test all APIs using this Postman collection:

[Postman Collection Link](https://www.postman.com/virtual-events/workspace/buiskut/collection/41464244-a36a28e7-7c3c-4bb8-8459-55de4641ff2a?action=share&creator=41464244)

---

## Test Coverage

The project includes unit tests for all API endpoints and core functionalities.

* **Estimated code coverage:** \~85–90%

This ensures that CRUD operations, authentication, and inventory management are thoroughly validated.

---

