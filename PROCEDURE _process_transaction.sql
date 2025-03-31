/*
This PL/SQL stored procedure comprehensively manages banking transactions, ensuring automated and secure control of customer transactions.

Procedure Objectives
Verifies that the account is active before processing the transaction.
Evaluates the balance before authorizing withdrawals or transfers.
Records the transaction in the bank history.
Detects and blocks potential fraud in suspicious transactions.
Eliminates fraudulent transactions when they are validated as such.
Correctly manages concurrency and validation errors.
*/

/*
Errors and Serious Problems in This Procedure

No Error Handling in SELECT INTO
Problem:
If SELECT INTO finds no data, the procedure fails.
If SELECT INTO returns more than one row, the procedure stops.

UPDATE WITHOUT FOR UPDATE
Problem:
Does not use FOR UPDATE, which can allow another transaction to modify the balance while this procedure is running.

Unnecessary Use of Subqueries in UPDATE
Executes the SELECT balance FROM accounts query unnecessarily.
Duplicates database access, slowing down the procedure.

No Error Handling in INSERT
Problem:
If INSERT fails due to a duplicate key (DUP_VAL_ON_INDEX), a fatal error will be generated without rollback.
There is no VALUE_ERROR handling in case the data type is not supported.

No COMMIT
Problem:
It doesn't commit changes, which can lead to inconsistencies if the transaction isn't closed properly.

Generic OTHERS Exception WITHOUT DETAILS
Problem:
It doesn't display the actual error message, which makes debugging difficult.
*/

CREATE OR REPLACE PROCEDURE process_transaction(
 p_transaction_id NUMBER
) ES
 -- Variables to store transaction data
 v_account_id NUMBER;
 v_dest_account_id NUMBER;
 v_transaction_type VARCHAR2(20);
 v_amount NUMBER;
 v_balance NUMBER;
 v_account_status VARCHAR2(20);
 v_existing_fraud NUMBER;
 v_status VARCHAR2(20);
 v_fraud_flag BOOLEAN := FALSE;

BEGIN
-- Get transaction details (NO EXCEPTION HANDLING)
SELECT account_id, dest_account_id, transaction_type, amount
INTO v_account_id, v_dest_account_id, v_transaction_type, v_amount
FROM transactions
WHERE transaction_id = p_transaction_id;

-- Get account details (NO FOR UPDATE, which can cause inconsistencies)
SELECT balance, account_status
INTO v_balance, v_account_status
FROM accounts
WHERE account_id = v_account_id;

-- Validate that the account is active (DOES NOT HANDLE INACTIVE ACCOUNT CASES)
IF v_account_status != 'Active' THEN
v_status := 'Rejected';
END IF;

-- Validate balance inefficiently (WITHOUT USING `EXCEPTION`)
 IF v_transaction_type IN ('Withdrawal', 'Transfer') THEN
 IF (SELECT balance FROM accounts WHERE account_id = v_account_id) < v_amount THEN
 RAISE_APPLICATION_ERROR(-20006, 'Insufficient funds.');
 END IF;
 END IF;

 -- MISIMPLEMENTED FRAUD DETECTION (Unnecessary nested query)
 SELECT COUNT(*)
 INTO v_existing_fraud
 FROM fraud_cases
 WHERE account_id = v_account_id
 AND transaction_date IN
 (SELECT transaction_date FROM fraud_cases WHERE transaction_date >= ADD_MONTHS(SYSDATE, -3));

 -- Erroneous fraud marking without clear conditions
 IF v_existing_fraud > 0 THEN
 v_fraud_flag := TRUE;
 END IF;

 -- Insert transaction WITHOUT ERROR HANDLING (If it fails, it stops everything)
 INSERT INTO transactions (transaction_id, account_id, dest_account_id, transaction_type, amount, transaction_date, status)
 VALUES (seq_transaction_id.NEXTVAL, v_account_id, v_dest_account_id, v_transaction_type, v_amount, SYSDATE, 'Pending');

 -- MISMANAGEMENT OF BALANCE (Query in subquery instead of updating directly)
 IF v_transaction_type IN ('Withdrawal', 'Transfer') THEN
 UPDATE accounts
 SET balance = (SELECT balance FROM accounts WHERE account_id = v_account_id) - v_amount
 WHERE account_id = v_account_id;
 ELSIF v_transaction_type = 'Deposit' THEN
 UPDATE accounts
 SET balance = (SELECT balance FROM accounts WHERE account_id = v_account_id) + v_amount
 WHERE account_id = v_account_id;
 END IF;
 -- Insert fraud WITHOUT ERROR HANDLING
 
/*
Key Validations
Verifies that the account is active and has a sufficient balance.
Locks the row (FOR UPDATE) to avoid concurrency inconsistencies.

Error and Exception Handling
NO_DATA_FOUND → If the account or transaction does not exist, a clear error is displayed.
TOO_MANY_ROWS → Avoids problems if there is duplicate data in the database.
DUP_VAL_ON_INDEX → Prevents duplicate insertions in transactions and fraud.
OTHERS → Captures any other errors with SQLERRM to facilitate debugging.

Fraud Management
If the transaction is greater than 10,000 and the user already has fraud recorded, it is marked as "Possible Fraud."
If fraud is detected, a record is inserted into fraud_cases.

Audit Logging
Each processed transaction is saved in the audit_log for traceability.
Prevent suspicious transactions from going unnoticed.
*/

CREATE OR REPLACE PROCEDURE process_transaction(
 p_transaction_id NUMBER
) ES
 -- Variables to store transaction data
 v_account_id NUMBER;
 v_dest_account_id NUMBER;
 v_transaction_type VARCHAR2(20);
 v_amount NUMBER;
 v_balance NUMBER;
 v_account_status VARCHAR2(20);
 v_existing_fraud NUMBER;
 v_status VARCHAR2(20);
 v_fraud_flag BOOLEAN := FALSE;

BEGIN
-- Get transaction details
BEGIN
SELECT account_id, dest_account_id, transaction_type, amount
INTO v_account_id, v_dest_account_id, v_transaction_type, v_amount
FROM transactions
WHERE transaction_id = p_transaction_id;
EXCEPTION
WHEN NO_DATA_FOUND THEN
RAISE_APPLICATION_ERROR(-20001, 'No transaction with the given ID was found.');
WHEN TOO_MANY_ROWS THEN
RAISE_APPLICATION_ERROR(-20002, 'Error: Multiple records exist for the same transaction.');
END;

-- Validate that the account exists and is active
BEGIN
SELECT balance, account_status
INTO v_balance, v_account_status
FROM accounts
WHERE account_id = v_account_id
FOR UPDATE; -- Lock the row to avoid inconsistencies in concurrency
EXCEPTION
WHEN NO_DATA_FOUND THEN
RAISE_APPLICATION_ERROR(-20003, 'Bank account not found.');
WHEN TOO_MANY_ROWS THEN
RAISE_APPLICATION_ERROR(-20004, 'Error: There are multiple accounts with the same ID.');
END;

-- If the account is not active, the transaction is rejected
IF v_account_status != 'Active' THEN
RAISE_APPLICATION_ERROR(-20005, 'The transaction cannot be processed. The account is inactive.');
END IF;

-- Balance validation for withdrawals and transfers
IF v_transaction_type IN ('Withdrawal', 'Transfer') AND v_balance < v_amount THEN
RAISE_APPLICATION_ERROR(-20006, 'Insufficient funds to complete the transaction.');
END IF;

-- Detect suspicious transactions (fraud)
BEGIN
SELECT COUNT(*)
INTO v_existing_fraud
FROM fraud_cases
WHERE account_id = v_account_id
AND transaction_date >= ADD_MONTHS(SYSDATE, -3); -- Last 3 months
EXCEPTION
WHEN NO_DATA_FOUND THEN
v_existing_fraud := 0;
END;

-- If the transaction is high-value and the user has previous fraud cases, flag this alert.
IF v_amount > 10000 AND v_existing_fraud > 0 THEN
v_fraud_flag := TRUE;
END IF;

-- Insert transaction into bank history
BEGIN
INSERT INTO transactions (transaction_id, account_id, dest_account_id, transaction_type, amount, transaction_date, status)
VALUES (seq_transaction_id. NEXTVAL, v_account_id, v_dest_account_id, v_transaction_type, v_amount, SYSDATE, 'Pending');
EXCEPTION
WHEN DUP_VAL_ON_INDEX THEN
RAISE_APPLICATION_ERROR(-20007, 'Error: Transaction already exists.');
WHEN VALUE_ERROR THEN
 RAISE_APPLICATION_ERROR(-20008, 'Data type error.');
 WHEN OTHERS THEN
 RAISE_APPLICATION_ERROR(-20009, 'Error inserting transaction: ' || SQLERRM);
 END;

 -- If the transaction was approved, update the account balance
 IF v_transaction_type IN ('Withdrawal', 'Transfer') THEN
 UPDATE accounts
 SET balance = balance - v_amount
 WHERE account_id = v_account_id;
 ELSIF v_transaction_type = 'Deposit' THEN
 UPDATE accounts
 SET balance = balance + v_amount
 WHERE account_id = v_account_id;
 END IF;

 -- If the transaction is suspicious, log in fraud_cases
 IF v_fraud_flag THEN
 BEGIN
 INSERT INTO fraud_cases (fraud_id, account_id, transaction_id, fraud_type, detection_date)
 VALUES (seq_fraud_id.NEXTVAL, v_account_id, p_transaction_id, 'Possible Fraud', SYSDATE);
 EXCEPTION
 WHEN DUP_VAL_ON_INDEX THEN
 RAISE_APPLICATION_ERROR(-20010, 'Error: The fraud case already exists.');
 WHEN OTHERS THEN
 RAISE_APPLICATION_ERROR(-20011, 'Error recording fraud: ' || SQLERRM);
 END;
 END IF;

 -- Record in audit log
 BEGIN
 INSERT INTO audit_log (log_id, account_id, transaction_id, action, log_date)
 VALUES (seq_log_id.NEXTVAL, v_account_id, p_transaction_id, 'Processed Transaction', SYSDATE);
 EXCEPTION
 WHEN OTHERS THEN
 RAISE_APPLICATION_ERROR(-20012, 'Error logging to audit log: ' || SQLERRM);
 END;

 -- Commit changes
 COMMIT;
EXCEPTION
 WHEN OTHERS THEN
 ROLLBACK;
 RAISE_APPLICATION_ERROR(-20099, 'Error processing transaction: ' || SQLERRM);
END process_transaction;
/