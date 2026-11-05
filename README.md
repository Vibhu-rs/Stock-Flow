# Stock Flow — store management and POS

Flask + MySQL store management app with inventory, purchasing, cashier/admin roles, POS billing, GST-aware receipts/invoices, returns/refunds, and CSV/PDF exports.

## Added billing features

- **Receipts and invoices:** completed sales receive an invoice number. The POS and Sales & returns screens can download a PDF receipt or tax invoice.
- **GST:** products have HSN and GST-rate fields. GST is calculated on the discounted taxable value per sale line. Same-state sales split GST into CGST + SGST; inter-state sales use IGST. Tax values and the rates used are saved with the sale, so later product edits do not change earlier invoices.
- **Returns/refunds:** an admin can process full or partial item returns, choose whether to put goods back into stock, and download a credit note. Refund values are based on the original discounted sale-line amount and original GST, not today's product price.
- **Exports:** admins can download sales, returns, and products as CSV files. PDFs are available for individual sales and return credit notes.

## Setup

1. Create a MySQL database and configure its connection in `.env` using `.env.example` as a template.
2. For a **new database**, run `schema.sql` once. If you are upgrading the database used by the current app, **do not drop or recreate the tables**: back it up first, then deploy the updated `app.py`. Its idempotent startup migration adds the new columns and return tables while preserving existing records.
3. Install dependencies and start the app:

   ```bash
   python -m venv .venv
   # Windows PowerShell: .venv\Scripts\Activate.ps1
   # macOS/Linux: source .venv/bin/activate
   pip install -r requirements.txt
   python app.py
   ```

4. Set a strong `JWT_SECRET`. Change the default admin password immediately after first login, and keep `.env` out of Git.

## GST configuration

Before assigning a non-zero GST rate to products, configure:

- `STORE_GSTIN`: the store's valid 15-character GSTIN.
- `STORE_STATE`: the store's state name, for example `Delhi`.
- `STORE_STATE_CODE`: the GST state code, for example `07`. The app can derive this from the first two characters of `STORE_GSTIN`, but setting it explicitly is clearer.
- `STORE_NAME`, `STORE_ADDRESS`, and optionally `STORE_PHONE` / `STORE_EMAIL` for the document header.

Add each product's HSN code and GST rate in **Inventory**. Add a business customer's GSTIN and state in **Customers**. At checkout, verify the place of supply and customer GSTIN. The listed product price is treated as GST-exclusive; the GST amount is added to it. If the store and destination state match, the app uses CGST + SGST; otherwise it uses IGST.

The app performs basic rate/state calculations; it does not validate HSN classifications, GST registration status, exemptions, place-of-supply exceptions, e-invoicing/e-way-bill requirements, statutory invoice numbering rules, or the correctness of your tax treatment. Have a qualified accountant verify the configuration and invoice format before using these documents as statutory GST records.

## Returns and refunds

Returns are admin-only. Select the quantity to return on the original sale. The server prevents returning more than the quantity not already returned. By default, returned stock is added back to inventory; untick **Restock returned items** for damaged/non-resalable goods. The app records the refund and credit note, but does not connect to a payment gateway or move money: issue the actual payment refund through your normal payment method.

## Exports

Open **Sales & returns** as an admin to export:

- Sales register (includes subtotal, discount, taxable value, CGST, SGST, IGST, total, customer GSTIN, and place of supply)
- Returns register (includes credit note and refund amount)
- Product list (includes HSN and GST rate)

## Deployment notes

Keep `.env`, virtual environments, and local secrets out of the repository. On Render or another host, set the environment variables in the service dashboard and point `DB_HOST` / credentials to your existing MySQL database. `ca.pem` may be included if your managed database provider requires a CA certificate; alternatively supply `DB_CA`.
