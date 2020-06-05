package Utils;

import Utils.SM3.SM3Util;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * @author FL
 * @date Created in 15:27 2020/6/4
 */
@Slf4j
public class SM3UtilTest {

    public static final String PWD_LENGTH_EX_MSG = "密码的长度必须等于6";

    /**
     * 密码
     */
    private String password;
    /**
     * 密码长度
     */
    private final Integer pwdLength = 6;

    /**
     * 密码加密组合之后
     */
    private String pwdEncryptAssembly;

    /**
     * 密码长度
     */
    private Integer pwdSize;


    /**
     * 密码加密最终结果
     */
    private String pwdEncrypt;

    @BeforeEach
    public void testbefore() {
        password = "135790";
        pwdSize = password.length();
        pwdEncryptAssembly = SM3Util.pwdEncryptAssembly(password);

    }

    @Test
    public void testEncrypt() {
        if (pwdSize.equals(pwdLength)) {
            log.info("您输入的密码:{}", password);
            log.info("您密码加密组合并组合:{}", pwdEncryptAssembly);
            pwdEncrypt = SM3Util.pwdEncrypt(password);
            log.info("最终组合密码结果:{}", pwdEncrypt);

        } else {
            log.info("错误信息:{}", PWD_LENGTH_EX_MSG);
        }
    }

}
