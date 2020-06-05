package Utils.SM3;


import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

/**
 * 紫云项目安全键盘加密规则
 * @author FL
 * @date Created in 11:16 2020/6/4
 */
public enum SM3Rule {

    /**
     * 转码规则
     * 0	fu
     * 1	pt
     * 2	jm
     * 3	mp
     * 4	ts
     * 5	gl
     * 6	io
     * 7	sb
     * 8	hx
     * 9	wr
     */
    ZERO("0", "fu"),
    ONE("1", "pt"),
    TWO("2", "jm"),
    THREE("3", "mp"),
    FOUR("4", "ts"),
    FIVE("5", "gl"),
    SIX("6", "io"),
    SEVEN("7", "sb"),
    EIGHT("8", "hx"),
    NINE("9", "wr")
    ;


    @Getter
    private String code;
    @Getter
    private String msg;

    SM3Rule(String code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public static String valueOfCode(String code) {
        for (SM3Rule sm3Rule : values()) {
            if (StringUtils.equals(code, sm3Rule.code)) {
                return sm3Rule.msg;
            }
        }
        throw new IllegalStateException("数字转换异常");
    }

}