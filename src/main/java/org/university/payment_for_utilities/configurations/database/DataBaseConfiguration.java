package org.university.payment_for_utilities.configurations.database;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

@Configuration
public class DataBaseConfiguration {
    @Bean
    public JdbcTemplate jdbcTemplate(){
        return new JdbcTemplate(dataSource());
    }

    @Bean
    public DataSource dataSource(){
        var dotenv = Dotenv.configure().load();

        var url = dotenv.get("DB_TEST_URL");
        var username = dotenv.get("DB_USERNAME");
        var password = dotenv.get("DB_PASSWORD");

        return DataSourceBuilder
                .create()
                .url(url)
                .username(username)
                .password(password)
                .build();
    }
}
