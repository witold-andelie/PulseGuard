-- @vuln application may concatenate input into this query; no SQL taint rule
SELECT * FROM orders WHERE id = '1' OR '1' = '1';
