
-- Tabla: customers
CREATE TABLE customers (
    customer_id      NUMBER PRIMARY KEY,
    full_name        VARCHAR2(100),
    account_type     VARCHAR2(20)
);

INSERT INTO customers VALUES (1, 'Alice Johnson', 'Savings');
INSERT INTO customers VALUES (2, 'Bob Smith', 'Checking');
INSERT INTO customers VALUES (3, 'Carla Gomez', 'Savings');
INSERT INTO customers VALUES (4, 'Daniel Lee', 'Checking');
INSERT INTO customers VALUES (5, 'Eva Rodríguez', 'Savings');

-- Tabla: transactions
CREATE TABLE transactions (
    transaction_id   NUMBER PRIMARY KEY,
    customer_id      NUMBER,
    transaction_type VARCHAR2(20),
    amount           NUMBER(12,2),
    transaction_date DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO transactions VALUES (101, 1, 'Deposit',     1000.00, TO_DATE('2024-01-10','YYYY-MM-DD'));
INSERT INTO transactions VALUES (102, 2, 'Withdrawal',  200.00,  TO_DATE('2024-02-15','YYYY-MM-DD'));
INSERT INTO transactions VALUES (103, 3, 'Deposit',     1500.00, TO_DATE('2024-03-20','YYYY-MM-DD'));
INSERT INTO transactions VALUES (104, 4, 'Withdrawal',  300.00,  TO_DATE('2024-04-25','YYYY-MM-DD'));
INSERT INTO transactions VALUES (105, 5, 'Deposit',     500.00,  TO_DATE('2024-06-01','YYYY-MM-DD'));

-- Tabla: account_balance
CREATE TABLE account_balance (
    customer_id NUMBER,
    balance     NUMBER(12,2),
    last_update DATE,
    PRIMARY KEY (customer_id),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO account_balance VALUES (1, 2000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO account_balance VALUES (2, 3500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO account_balance VALUES (3, 1800.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO account_balance VALUES (4, 2200.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO account_balance VALUES (5, 4000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));

-- Tabla: daily_balance
CREATE TABLE daily_balance (
    record_id   NUMBER PRIMARY KEY,
    customer_id NUMBER,
    balance     NUMBER(12,2),
    balance_date DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO daily_balance VALUES (1, 1, 2100.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO daily_balance VALUES (2, 2, 3300.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO daily_balance VALUES (3, 3, 1700.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO daily_balance VALUES (4, 4, 2500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO daily_balance VALUES (5, 5, 3900.00, TO_DATE('2024-06-01','YYYY-MM-DD'));

-- Tabla: evaluates
CREATE TABLE evaluates (
    evaluator_id  NUMBER PRIMARY KEY,
    customer_id   NUMBER,
    score         NUMBER(3),
    evaluation_date DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO evaluates VALUES (1, 1, 85, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO evaluates VALUES (2, 2, 90, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO evaluates VALUES (3, 3, 70, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO evaluates VALUES (4, 4, 60, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO evaluates VALUES (5, 5, 95, TO_DATE('2024-06-01','YYYY-MM-DD'));

-- Tabla: suspicious_activity
CREATE TABLE suspicious_activity (
    activity_id     NUMBER PRIMARY KEY,
    customer_id     NUMBER,
    description     VARCHAR2(255),
    report_date     DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO suspicious_activity VALUES (1, 2, 'Multiple logins from different IPs', TO_DATE('2024-05-10','YYYY-MM-DD'));
INSERT INTO suspicious_activity VALUES (2, 3, 'Unusual withdrawal pattern', TO_DATE('2024-05-12','YYYY-MM-DD'));
INSERT INTO suspicious_activity VALUES (3, 4, 'Login at 3 AM', TO_DATE('2024-05-14','YYYY-MM-DD'));
INSERT INTO suspicious_activity VALUES (4, 1, 'Failed login attempts', TO_DATE('2024-05-16','YYYY-MM-DD'));
INSERT INTO suspicious_activity VALUES (5, 5, 'Excessive fund transfers', TO_DATE('2024-05-18','YYYY-MM-DD'));

-- Tabla: suspicious_transactions
CREATE TABLE suspicious_transactions (
    suspicious_id     NUMBER PRIMARY KEY,
    transaction_id    NUMBER,
    reason            VARCHAR2(255),
    flagged_on        DATE,
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);

INSERT INTO suspicious_transactions VALUES (1, 102, 'High amount withdrawal flagged by rule engine', TO_DATE('2024-02-15','YYYY-MM-DD'));
INSERT INTO suspicious_transactions VALUES (2, 104, 'Repeated withdrawals', TO_DATE('2024-04-25','YYYY-MM-DD'));
INSERT INTO suspicious_transactions VALUES (3, 105, 'Deposit from unknown source', TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO suspicious_transactions VALUES (4, 103, 'Unusual deposit timing', TO_DATE('2024-03-20','YYYY-MM-DD'));
INSERT INTO suspicious_transactions VALUES (5, 101, 'Account under monitoring', TO_DATE('2024-01-10','YYYY-MM-DD'));

-- Tabla: transaction_stats
CREATE TABLE transaction_stats (
    stat_id           NUMBER PRIMARY KEY,
    customer_id       NUMBER,
    total_transactions NUMBER,
    total_amount       NUMBER(12,2),
    last_updated       DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO transaction_stats VALUES (1, 1, 10, 5000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_stats VALUES (2, 2, 15, 7500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_stats VALUES (3, 3, 8, 4000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_stats VALUES (4, 4, 12, 3000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_stats VALUES (5, 5, 5, 2500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));

-- Tabla: transaction_summary
CREATE TABLE transaction_summary (
    summary_id      NUMBER PRIMARY KEY,
    customer_id     NUMBER,
    total_deposits  NUMBER(12,2),
    total_withdrawals NUMBER(12,2),
    summary_date    DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

INSERT INTO transaction_summary VALUES (1, 1, 3000.00, 500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_summary VALUES (2, 2, 5000.00, 800.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_summary VALUES (3, 3, 6000.00, 1000.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_summary VALUES (4, 4, 4000.00, 500.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
INSERT INTO transaction_summary VALUES (5, 5, 3500.00, 400.00, TO_DATE('2024-06-01','YYYY-MM-DD'));
