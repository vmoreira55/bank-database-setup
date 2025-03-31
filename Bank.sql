/*
Scenario: Bank - Customer and Transaction Analysis

For this new case, we will work with a banking system. The objective is to obtain a detailed report on customers and transactions, including:

Customers with the largest deposits and withdrawals in the last year
Total account balance after each transaction
Difference between the amount deposited and withdrawn
Suspicious transactions (large deposits and withdrawals on the same day)
Customer classification by financial activity
*/

/*
Poorly optimized query with poor performance

Calculations are repeated for deposits, withdrawals, net difference and ending balance, causing the database to have to run the same queries over and over again.

A nested subquery with IN is used, which duplicates the work and makes the query slow on large databases.

SUM(CASE WHEN transaction_type = 'Deposit' THEN amount ELSE -amount END) is recalculated up to 3 times in the same query.

ALL transactions in the bank's history are reviewed, rather than just those from the last year.

When doing operations on columns (SUM(CASE WHEN ... END)) inside WHERE, the indexing of transaction_date is broken.
*/

-- To get the information of each customer, we use multiple repetitive subqueries
SELECT
 c.customer_id,
 c.full_name,
 c.account_type,

 -- Unnecessary subquery to calculate total deposits
 (SELECT SUM(amount) FROM transactions WHERE customer_id = c.customer_id AND transaction_type = 'Deposit') AS total_deposits,

 -- Unnecessary subquery to calculate total withdrawals
 (SELECT SUM(amount) FROM transactions WHERE customer_id = c.customer_id AND transaction_type = 'Withdrawal') AS total_withdrawals,

 -- Bad subquery to calculate the net difference
 ((SELECT SUM(amount) FROM transactions WHERE customer_id = c.customer_id AND transaction_type = 'Deposit')
 -
 (SELECT SUM(amount) FROM transactions WHERE customer_id = c.customer_id AND transaction_type = 'Withdrawal')) AS net_difference,

 -- Subquery to obtain final balance (the calculation is repeated)
 (SELECT SUM(CASE WHEN transaction_type = 'Deposit' THEN amount ELSE -amount END)
 FROM transactions WHERE customer_id = c.customer_id) AS final_balance,

 -- Client classification using CASE with redundant conditions
 CASE
 WHEN (SELECT SUM(CASE WHEN transaction_type = 'Deposit' THEN amount ELSE -amount END)
 FROM transactions WHERE customer_id = c.customer_id) > 50000
 THEN 'High Value Customer'
 WHEN (SELECT SUM(CASE WHEN transaction_type = 'Deposit' THEN amount ELSE -amount END)
 FROM transactions WHERE customer_id = c.customer_id) BETWEEN 10000 AND 50000
 THEN 'Medium Value Customer'
 ELSE 'Low Value Customer'
 END AS customer_category,

 -- Counting suspicious transactions with subquery in the SELECT (very inefficient)
 (SELECT COUNT(*) FROM transactions t1
 WHERE t1.customer_id = c.customer_id
 AND t1.transaction_date IN
 (SELECT t2.transaction_date FROM transactions t2
 WHERE t2.customer_id = c.customer_id
 GROUP BY t2.transaction_date
 HAVING SUM(CASE WHEN t2.transaction_type = 'Deposit' THEN t2.amount ELSE 0 END) > 5000
 AND SUM(CASE WHEN t2.transaction_type = 'Withdrawal' THEN t2.amount ELSE 0 END) > 5000))
 ACE suspicious_activity_count

FROM customers c;

/*
CTE transaction_summary
Gets the total deposits and withdrawals per customer in the last year.
Uses SUM(CASE WHEN ... THEN ... ELSE ... END) to calculate deposits and withdrawals separately.

CTE suspicious_transactions
Detects customers who have made large deposits and withdrawals on the same day.
Uses HAVING to filter out amounts greater than 5000 for both deposits and withdrawals.
CTE account_balance

Calculates the customer's ending balance by subtracting deposits and withdrawals.
Main Query

Joins all information using LEFT JOIN to include all customers, even if they have no transactions.
Categorizes customers by their ending balance (customer_category).
Counts suspicious transactions per customer (suspicious_activity_count).
*/

WITH transaction_summary AS (
    -- Obtain the total deposits and withdrawals per customer in the last year
    SELECT 
        t.customer_id,
        SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE 0 END) AS total_deposits,
        SUM(CASE WHEN t.transaction_type = 'Withdrawal' THEN t.amount ELSE 0 END) AS total_withdrawals,
        COUNT(t.transaction_id) AS transaction_count
    FROM transactions t
    WHERE t.transaction_date >= ADD_MONTHS(TRUNC(SYSDATE), -12)
    GROUP BY t.customer_id
),

suspicious_transactions AS (
    -- Identify suspicious transactions: High deposits and withdrawals on the same day
    SELECT 
        t.customer_id,
        t.transaction_date,
        SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE 0 END) AS daily_deposits,
        SUM(CASE WHEN t.transaction_type = 'Withdrawal' THEN t.amount ELSE 0 END) AS daily_withdrawals
    FROM transactions t
    GROUP BY t.customer_id, t.transaction_date
    HAVING SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE 0 END) > 5000
       AND SUM(CASE WHEN t.transaction_type = 'Withdrawal' THEN t.amount ELSE 0 END) > 5000
),

account_balance AS (
    -- Calculate the total balance per customer
    SELECT 
        t.customer_id,
        SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE -t.amount END) AS final_balance
    FROM transactions t
    GROUP BY t.customer_id
)

-- Final query that joins all previous results
SELECT 
    c.customer_id,
    c.full_name,
    c.account_type,
    ts.total_deposits,
    ts.total_withdrawals,
    (ts.total_deposits - ts.total_withdrawals) AS net_difference,
    ab.final_balance,
    CASE 
        WHEN ab.final_balance > 50000 THEN 'High Value Customer'
        WHEN ab.final_balance BETWEEN 10000 AND 50000 THEN 'Medium Value Customer'
        ELSE 'Low Value Customer'
    END AS customer_category,
    COUNT(st.transaction_date) AS suspicious_activity_count
FROM customers c
LEFT JOIN transaction_summary ts ON c.customer_id = ts.customer_id
LEFT JOIN account_balance ab ON c.customer_id = ab.customer_id
LEFT JOIN suspicious_transactions st ON c.customer_id = st.customer_id
GROUP BY c.customer_id, c.full_name, c.account_type, ts.total_deposits, ts.total_withdrawals, ab.final_balance;
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/*
Scenario: Bank - Fraud and Customer Activity Analysis

This advanced query will analyze banking transactions to detect fraud and suspicious activity.
It includes: 
Customers with suspicious activity (duplicate transactions, withdrawals in different countries on the same day, transfers to themselves, etc.).
Average and median deposits/withdrawals over the last 6 months to detect anomalous amounts.
Daily balance history to see sudden changes.
VIP customers and their relationship with high-value transactions.
Ranking of customers with the most transactions.
*/

/*
Poorly optimized query with poor performance

Calculations are repeated for each row, instead of calculating them once and joining them with a JOIN or WITH (CTE).

Using EXISTS instead of JOIN
Evaluates a subquery for each transaction in the database.
Breaks indexes and forces a full table scan.

Nested subqueries in CASE statements
The same information is recalculated multiple times.
This unnecessarily increases processing load.

The query takes all transactions from the entire bank history, rather than just those from the last 6 months.
*/

-- To obtain each customer's information, we used multiple repetitive subqueries.
SELECT
c.customer_id,
c.full_name,
c.account_type,
c.country,
c.is_vip,

-- Redundant subquery to calculate average deposits
(SELECT AVG(t.amount) FROM transactions t WHERE t.customer_id = c.customer_id AND t.transaction_type = 'Deposit') AS avg_deposit,

-- Poorly crafted subquery to calculate median deposits
(SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY t.amount)
FROM transactions t WHERE t.customer_id = c.customer_id AND t.transaction_type = 'Deposit') AS median_deposit,

-- Repeated subquery for average withdrawals
(SELECT AVG(t.amount) FROM transactions t WHERE t.customer_id = c.customer_id AND t.transaction_type = 'Withdrawal') AS avg_withdrawal,

 -- Repeated subquery for median withdrawals
 (SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY t.amount)
 FROM transactions t WHERE t.customer_id = c.customer_id AND t.transaction_type = 'Withdrawal') AS median_withdrawal,

 -- Subquery to get the customer's most recent balance
 (SELECT SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE -t.amount END)
 FROM transactions t WHERE t.customer_id = c.customer_id) AS latest_balance,

 -- Suspicious activity detection with subqueries nested and unnecessary
 (SELECT COUNT(*) FROM transactions t1
 WHERE t1.customer_id = c.customer_id
 AND t1.transaction_date IN
 (SELECT t2.transaction_date FROM transactions t2
 WHERE t2.customer_id = c.customer_id
 GROUP BY t2.transaction_date
 HAVING SUM(CASE WHEN t2.transaction_type = 'Deposit' THEN t2.amount ELSE 0 END) > 5000
 AND SUM(CASE WHEN t2.transaction_type = 'Withdrawal' THEN t2.amount ELSE 0 END) > 5000))
 AS cross_country_withdrawals,

 -- Inefficient subquery to find duplicate transactions
 (SELECT COUNT(*) FROM transactions t1
 WHERE t1.customer_id = c.customer_id
 AND EXISTS (
 SELECT 1 FROM transactions t2
 WHERE t2.customer_id = t1.customer_id
 AND t2.amount = t1.amount
 AND t2.transaction_date = t1.transaction_date
 AND t2.transaction_id <> t1.transaction_id))
 AS duplicate_transactions,

 -- Unnecessary subquery to detect transfers to themselves
 (SELECT COUNT(*) FROM transactions t WHERE t.customer_id = c.customer_id
 AND t.transaction_type = 'Transfer' AND t.customer_id = t.destination_customer)
 AS self_transfers,

 -- Risk classification with repeated subqueries and unnecessary calculations
 (CASE
 WHEN (SELECT COUNT(*) FROM transactions t WHERE t.customer_id = c.customer_id
 AND EXISTS (
 SELECT 1 FROM transactions t2
 WHERE t2.customer_id = t.customer_id
 AND t2.amount = t.amount
 AND t2.transaction_date = t.transaction_date
 AND t2.transaction_id <> t.transaction_id)) > 2
 THEN 'High Risk'
 WHEN (SELECT AVG(t.amount) FROM transactions t WHERE t.customer_id = c.customer_id
 AND t.transaction_type = 'Withdrawal') >
 (SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY t.amount)
 FROM transactions t WHERE t.customer_id = c.customer_id
 AND t.transaction_type = 'Withdrawal') * 2
 THEN 'Moderate Risk'
 ELSE 'Low Risk'
 END) AS risk_level

FROM customers c;

/*
Transaction_stats (Statistical Analysis)

Calculates the average and median of each customer's deposits and withdrawals.
Uses PERCENTILE_CONT(0.5) to correctly calculate the median.
Identify anomalous values by comparing the average to the median.

Daily_balance (Daily Balance)
Calculates the customer's balance on each date using SUM() OVER (PARTITION BY customer_id ORDER BY transaction_date).
Allows you to see sharp fluctuations in the balance.

Suspicious_activity (Fraud Detection)
Detects withdrawals in different countries on the same day using a subquery in EXISTS().
Identifies duplicate transactions (same amount, same customer, same date).
Finds transfers to themselves.

Risk_level (Risk Rating)
"High Risk" if there are withdrawals in different countries or multiple duplicate transactions.
"Moderate Risk" if the average withdrawal is more than double the median.
"Low Risk" if there are no anomalies.
*/
WITH transaction_stats AS (
 -- Obtain statistics per client (average and median deposits/withdrawals in the last 6 months)
 SELECT
 t.customer_id,
 AVG(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE NULL END) AS avg_deposit,
 PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY CASE WHEN t.transaction_type = 'Deposit' THEN t.amount END) AS median_deposit,
 AVG(CASE WHEN t.transaction_type = 'Withdrawal' THEN t.amount ELSE NULL END) AS avg_withdrawal,
 PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY CASE WHEN t.transaction_type = 'Withdrawal' THEN t.amount END) AS median_withdrawal
 FROM transactions t
 WHERE t.transaction_date >= ADD_MONTHS(TRUNC(SYSDATE), -6)
 GROUP BY t.customer_id
),

daily_balance AS (
 -- Calculate the daily balance of each client
 SELECT
 t.customer_id,
 t.transaction_date,
 SUM(CASE WHEN t.transaction_type = 'Deposit' THEN t.amount ELSE -t.amount END)
 OVER (PARTITION BY t.customer_id ORDER BY t.transaction_date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
 AS daily_balance
 FROM transactions t
),

suspicious_activity AS (
 -- Detect suspicious activity:
 -- 1. Withdrawals in different countries on the same day
 -- 2. Duplicate transactions (same amount and date)
 -- 3. Transfers to themselves
 SELECT
 t.customer_id,
 COUNT(DISTINCT CASE WHEN EXISTS (
 SELECT 1 FROM transactions t2
 WHERE t2.customer_id = t.customer_id
 AND t2.transaction_type = 'Withdrawal'
 AND t2.transaction_date = t.transaction_date
 AND t2.location <> t.location
 ) THEN t.transaction_id END) AS cross_country_withdrawals,

 COUNT(DISTINCT CASE WHEN EXISTS (
 SELECT 1 FROM transactions t2
 WHERE t2.customer_id = t.customer_id
 AND t2.amount = t.amount
 AND t2.transaction_date = t.transaction_date
 AND t2.transaction_id <> t.transaction_id
 ) THEN t.transaction_id END) AS duplicate_transactions,

 COUNT(DISTINCT CASE WHEN t.transaction_type = 'Transfer'
 AND t.customer_id = t.destination_customer
 THEN t.transaction_id END) AS self_transfers
 FROM transactions t
 GROUP BY t.customer_id
)

-- Final query that unites all statistics and detected anomalies
SELECT
 c.customer_id,
 c.full_name,
 c.account_type,
 c.country,
 c.is_vip,
 ts.avg_deposit,
 ts.median_deposit,
 ts.avg_withdrawal,
 ts.median_withdrawal,
 db.daily_balance AS latest_balance,
 sa.cross_country_withdrawals,
 sa.duplicate_transactions,
 sa.self_transfers,
 CASE
 WHEN sa.cross_country_withdrawals > 1 OR sa.duplicate_transactions > 2 OR sa.self_transfers > 0 THEN 'High Risk'
 WHEN ts.avg_withdrawal > ts.median_withdrawal * 2 THEN 'Moderate Risk'
 ELSE 'Low Risk'
 END AS risk_level
FROM customers c
LEFT JOIN transaction_stats ts ON c.customer_id = ts.customer_id
LEFT JOIN daily_balance db ON c.customer_id = db.customer_id
 AND db.transaction_date = (SELECT MAX(transaction_date) FROM transactions WHERE customer_id = c.customer_id)
LEFT JOIN suspicious_activity sa ON c.customer_id = sa.customer_id
ORDER BY risk_level DESC, sa.duplicate_transactions DESC, c.is_vip DESC;