%let owner = user_input;
proc sql;
    select * from orders where owner = "&owner";
quit;
