import org.springframework.web.bind.annotation.RequestParam;
import java.sql.Statement;
class Orders {
    void order(@RequestParam("id") String id, Statement stmt) throws Exception {
        String query = "SELECT * FROM orders WHERE id = '" + id + "'";
        stmt.execute(query);
    }
}
