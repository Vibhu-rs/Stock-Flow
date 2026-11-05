-- Stock Flow baseline + billing/GST tables.
-- Run this only when creating a brand-new database. Existing databases are upgraded
-- automatically by app.py; take a DB backup before deploying that migration.

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'cashier'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sku VARCHAR(80) NULL UNIQUE,
  name VARCHAR(180) NOT NULL,
  price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  cost DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  stock INT NOT NULL DEFAULT 0,
  reorder_level INT NOT NULL DEFAULT 0,
  hsn_code VARCHAR(20) NULL,
  gst_rate DECIMAL(5,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS customers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(180) NOT NULL,
  phone VARCHAR(40) NULL,
  email VARCHAR(180) NULL,
  gstin VARCHAR(20) NULL,
  state VARCHAR(100) NULL,
  address TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS suppliers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(180) NOT NULL,
  phone VARCHAR(40) NULL,
  email VARCHAR(180) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sales (
  id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NULL,
  user_id INT NULL,
  total DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  discount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  subtotal DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  taxable_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  cgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  sgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  igst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  tax_total DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  invoice_no VARCHAR(40) NULL,
  place_of_supply VARCHAR(100) NULL,
  customer_gstin VARCHAR(20) NULL,
  store_gstin VARCHAR(20) NULL,
  gst_state VARCHAR(100) NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'completed',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_sales_invoice_no (invoice_no),
  KEY idx_sales_created_at (created_at),
  KEY idx_sales_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sale_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sale_id INT NOT NULL,
  product_id INT NULL,
  qty INT NOT NULL,
  price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  hsn_code VARCHAR(20) NULL,
  tax_rate DECIMAL(5,2) NOT NULL DEFAULT 0.00,
  discount_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  taxable_value DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  cgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  sgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  igst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  returned_qty INT NOT NULL DEFAULT 0,
  KEY idx_sale_items_sale (sale_id),
  KEY idx_sale_items_product (product_id),
  CONSTRAINT fk_sale_items_sale FOREIGN KEY (sale_id) REFERENCES sales(id),
  CONSTRAINT fk_sale_items_product FOREIGN KEY (product_id) REFERENCES products(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS purchase_orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  supplier_id INT NOT NULL,
  total DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_purchase_orders_supplier (supplier_id),
  CONSTRAINT fk_po_supplier FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS po_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  po_id INT NOT NULL,
  product_id INT NOT NULL,
  qty INT NOT NULL,
  cost DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  KEY idx_po_items_po (po_id),
  CONSTRAINT fk_po_items_po FOREIGN KEY (po_id) REFERENCES purchase_orders(id),
  CONSTRAINT fk_po_items_product FOREIGN KEY (product_id) REFERENCES products(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sales_returns (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  sale_id BIGINT NOT NULL,
  user_id BIGINT NULL,
  return_no VARCHAR(40) NULL UNIQUE,
  reason VARCHAR(250) NULL,
  refund_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  restocked TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sales_returns_sale (sale_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sales_return_items (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  return_id BIGINT NOT NULL,
  sale_item_id BIGINT NOT NULL,
  product_id BIGINT NULL,
  qty INT NOT NULL,
  taxable_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  cgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  sgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  igst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  refund_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  INDEX idx_return_items_return (return_id),
  INDEX idx_return_items_sale_item (sale_item_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
