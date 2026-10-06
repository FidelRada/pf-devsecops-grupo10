package bo.edu.devsecops;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DevSecOpsLabApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void productSearchIsAvailable() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Laptop"))
                .andExpect(status().isOk());
    }

    @Test
    void adminEndpointIsCurrentlyExposedForTheLab() throws Exception {
        mockMvc.perform(get("/api/admin/users/1"))
                .andExpect(status().isOk());
    }
}
