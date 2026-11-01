import org.springframework.web.bind.annotation.RequestParam;
import java.sql.Connection;
class Orders {
    void order(@RequestParam("id") String id, Connection conn) throws Exception {
        var stmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?");
        stmt.setString(1, id);
        stmt.execute();
    }
}
