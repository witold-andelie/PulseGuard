-- @vuln example of SQL text after unsafe interpolation, no request-source evidence
DELETE FROM orders WHERE owner = '' OR '1' = '1';
