import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Orders {
    void order(HttpServletRequest req, Statement stmt) throws Exception {
        String id = req.getParameter("id"); // @vuln SQL injection
        String query = "SELECT * FROM orders WHERE id = '" + id + "'";
        stmt.executeQuery(query);
    }
}
