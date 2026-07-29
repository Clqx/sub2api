CREATE TABLE products (
  id UUID PRIMARY KEY,
  sku TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price_micros BIGINT NOT NULL CHECK (price_micros > 0),
  currency TEXT NOT NULL DEFAULT 'CNY' CHECK (currency ~ '^[A-Z]{3}$'),
  benefit_type TEXT NOT NULL CHECK (benefit_type IN ('balance', 'subscription')),
  value_micros BIGINT NOT NULL CHECK (value_micros > 0),
  group_id BIGINT,
  validity_days INTEGER,
  purchase_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft', 'active', 'archived')),
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (
    (benefit_type = 'balance' AND group_id IS NULL AND validity_days IS NULL)
    OR
    (benefit_type = 'subscription' AND group_id > 0 AND validity_days > 0)
  )
);

ALTER TABLE redeem_codes
  ADD COLUMN product_id UUID REFERENCES products(id);

CREATE INDEX idx_products_public_order
  ON products(status, sort_order, created_at DESC);
CREATE INDEX idx_codes_product
  ON redeem_codes(product_id, created_at DESC);
