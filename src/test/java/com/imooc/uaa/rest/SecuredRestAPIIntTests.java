package com.imooc.uaa.rest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SecuredRestAPIIntTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    public void setup() {
        mvc = MockMvcBuilders
            .webAppContextSetup(context)
            .apply(springSecurity()) //需要检查权限的配置
            .build();
    }

    /** .antMatchers("/api/**").hasRole("USER")
     * 对于api开头的resource 有角色user 需要认证的 那为什么
     * apply(springSecurity()) 加了这个配置就需要认证 ，引入@WithMockUser
     * @throws Exception
     */
    @WithMockUser(value="user",roles={"USER"}) //提供一个虚拟用户 默认给的角色就是user
    @Test
    public void givenAuthRequest_shouldSucceedWith200() throws Exception {
        mvc.perform(get("/api/me").contentType(MediaType.APPLICATION_JSON))
            .andDo(print())
            .andExpect(status().isOk());
    }
}
