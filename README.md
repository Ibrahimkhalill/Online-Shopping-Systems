# Online Shopping System

A Django e-commerce storefront: product catalogue, cart, checkout and customer accounts.

## Data model

Defined in `store/models.py`:

| Model | Purpose |
|---|---|
| `Customer` | Shopper profile linked to a Django user |
| `Product` | Catalogue item |
| `Order` | Cart / placed order |
| `OrderItem` | Line item within an order |
| `ShippingAdress` | Delivery address for an order |

## Stack

- Django 3.2
- `django-crispy-forms` 1.14 for form rendering
- Pillow for product images
- SQLite (development default)

## Project layout

```
ecommerce/       # settings, root urls, wsgi
store/           # catalogue, cart, checkout
accounts/        # registration and login
static/          # css, js, product images
requirements.txt
manage.py
```

Both `store.urls` and `accounts.urls` are mounted at `/`, with the Django admin at `/admin/`.

## Getting started

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000/ for the storefront and http://127.0.0.1:8000/admin/ to add products.

## Notes

- This repository is a near-duplicate of [`Online-Shopping-System`](https://github.com/Ibrahimkhalill/Online-Shopping-System) (singular). This one is the later copy and is the one with a `requirements.txt`.
- `db.sqlite3` is committed. Delete it and re-run `migrate` for a clean database.
