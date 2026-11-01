import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Orders {
    void order(HttpServletRequest req, Connection conn) throws Exception {
        String id = req.getParameter("id"); // @safe bound value
        var stmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        stmt.setString(1, id);
        stmt.executeQuery();
    }
}
