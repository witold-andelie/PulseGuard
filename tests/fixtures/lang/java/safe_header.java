import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
class Orders {
    void update(HttpServletRequest req, Connection conn) throws Exception {
        String owner = req.getHeader("X-Owner");
        var stmt = conn.prepareStatement("DELETE FROM orders WHERE owner = ?");
        stmt.setString(1, owner);
        stmt.executeUpdate();
    }
}
