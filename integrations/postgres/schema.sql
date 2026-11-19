-- TPC-C-like schema (NewOrder and Payment only), scaled down.
-- The two procedures return the after-image of every row they write, split
-- into rows that are not personal data ("public": warehouse, district,
-- stock) and rows that belong to the customer who made the request
-- ("private": customer, orders, order lines, history). The front end logs
-- those images in the sealed log; PostgreSQL is a materialised copy that
-- can be rebuilt from the log (replay.py).

DROP TABLE IF EXISTS warehouse, district, customer, item, stock, orders, new_order,
                     order_line, history, usertable CASCADE;

CREATE TABLE warehouse (w_id int PRIMARY KEY, w_name text, w_ytd numeric(12,2));
CREATE TABLE district (d_w_id int, d_id int, d_name text, d_ytd numeric(12,2), d_next_o_id int,
                       PRIMARY KEY (d_w_id, d_id));
CREATE TABLE customer (c_w_id int, c_d_id int, c_id int, c_first text, c_last text, c_street text,
                       c_city text, c_balance numeric(12,2), c_ytd_payment numeric(12,2),
                       c_payment_cnt int, c_data text, PRIMARY KEY (c_w_id, c_d_id, c_id));
CREATE TABLE item (i_id int PRIMARY KEY, i_name text, i_price numeric(5,2));
CREATE TABLE stock (s_w_id int, s_i_id int, s_quantity int, s_ytd int, s_order_cnt int,
                    PRIMARY KEY (s_w_id, s_i_id));
CREATE TABLE orders (o_w_id int, o_d_id int, o_id int, o_c_id int, o_entry_d timestamptz, o_ol_cnt int,
                     PRIMARY KEY (o_w_id, o_d_id, o_id));
CREATE TABLE new_order (no_w_id int, no_d_id int, no_o_id int, PRIMARY KEY (no_w_id, no_d_id, no_o_id));
CREATE TABLE order_line (ol_w_id int, ol_d_id int, ol_o_id int, ol_number int, ol_i_id int,
                         ol_quantity int, ol_amount numeric(8,2),
                         PRIMARY KEY (ol_w_id, ol_d_id, ol_o_id, ol_number));
CREATE TABLE history (h_id bigserial PRIMARY KEY, h_c_w_id int, h_c_d_id int, h_c_id int, h_amount numeric(8,2),
                      h_date timestamptz, h_data text);
CREATE INDEX orders_by_customer ON orders (o_w_id, o_d_id, o_c_id);
CREATE INDEX history_by_customer ON history (h_c_w_id, h_c_d_id, h_c_id);

-- YCSB: one row per key, each key owned by one user
CREATE TABLE usertable (ycsb_key int PRIMARY KEY, owner int, field0 text);

CREATE OR REPLACE FUNCTION new_order(w int, d int, c int, items int[], qtys int[])
RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  oid int; dist record; st record; price numeric; n int := array_length(items, 1);
  pub json[] := '{}'; priv json[] := '{}'; o record; ol record; i int;
BEGIN
  UPDATE district SET d_next_o_id = d_next_o_id + 1 WHERE d_w_id = w AND d_id = d
    RETURNING * INTO dist;
  oid := dist.d_next_o_id - 1;
  pub := pub || json_build_object('t', 'district', 'r', row_to_json(dist));
  INSERT INTO orders VALUES (w, d, oid, c, now(), n) RETURNING * INTO o;
  priv := priv || json_build_object('t', 'orders', 'r', row_to_json(o));
  INSERT INTO new_order VALUES (w, d, oid);
  priv := priv || json_build_object('t', 'new_order', 'r', json_build_object('no_w_id', w, 'no_d_id', d, 'no_o_id', oid));
  FOR i IN 1..n LOOP
    SELECT i_price INTO price FROM item WHERE i_id = items[i];
    UPDATE stock SET s_quantity = CASE WHEN s_quantity - qtys[i] >= 10 THEN s_quantity - qtys[i]
                                       ELSE s_quantity - qtys[i] + 91 END,
                     s_ytd = s_ytd + qtys[i], s_order_cnt = s_order_cnt + 1
      WHERE s_w_id = w AND s_i_id = items[i] RETURNING * INTO st;
    pub := pub || json_build_object('t', 'stock', 'r', row_to_json(st));
    INSERT INTO order_line VALUES (w, d, oid, i, items[i], qtys[i], qtys[i] * price) RETURNING * INTO ol;
    priv := priv || json_build_object('t', 'order_line', 'r', row_to_json(ol));
  END LOOP;
  RETURN json_build_object('public', to_json(pub), 'private', to_json(priv));
END $$;

CREATE OR REPLACE FUNCTION payment(w int, d int, c int, amount numeric)
RETURNS json LANGUAGE plpgsql AS $$
DECLARE wh record; dist record; cu record; h record;
BEGIN
  UPDATE warehouse SET w_ytd = w_ytd + amount WHERE w_id = w RETURNING * INTO wh;
  UPDATE district SET d_ytd = d_ytd + amount WHERE d_w_id = w AND d_id = d RETURNING * INTO dist;
  UPDATE customer SET c_balance = c_balance - amount, c_ytd_payment = c_ytd_payment + amount,
                      c_payment_cnt = c_payment_cnt + 1
    WHERE c_w_id = w AND c_d_id = d AND c_id = c RETURNING * INTO cu;
  INSERT INTO history (h_c_w_id, h_c_d_id, h_c_id, h_amount, h_date, h_data)
    VALUES (w, d, c, amount, now(), 'payment') RETURNING * INTO h;
  RETURN json_build_object(
    'public', json_build_array(json_build_object('t', 'warehouse', 'r', row_to_json(wh)),
                               json_build_object('t', 'district', 'r', row_to_json(dist))),
    'private', json_build_array(json_build_object('t', 'customer', 'r', row_to_json(cu)),
                                json_build_object('t', 'history', 'r', row_to_json(h))));
END $$;

CREATE OR REPLACE FUNCTION ycsb_update(k int, v text)
RETURNS json LANGUAGE plpgsql AS $$
DECLARE u record;
BEGIN
  UPDATE usertable SET field0 = v WHERE ycsb_key = k RETURNING * INTO u;
  RETURN json_build_object('public', '[]'::json,
                           'private', json_build_array(json_build_object('t', 'usertable', 'r', row_to_json(u))));
END $$;
