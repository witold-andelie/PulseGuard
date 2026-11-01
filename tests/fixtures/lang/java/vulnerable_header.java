import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Orders {
    void update(HttpServletRequest req, Statement stmt) throws Exception {
        String owner = req.getHeader("X-Owner");
        stmt.executeUpdate("DELETE FROM orders WHERE owner = '" + owner + "'");
    }
}
