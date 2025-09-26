package com.jeecg.modules.jmreport.extend;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.exception.NotLoginException;
import cn.dev33.satoken.stp.StpUtil;
import com.jeecg.modules.jmreport.satoken.config.SecurityConfig;
import com.jeecg.modules.jmreport.satoken.util.AjaxRequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jeecg.modules.jmreport.api.JmReportTokenServiceI;
import org.jeecg.modules.jmreport.common.constant.JmConst;
import org.jeecg.modules.jmreport.common.expetion.JimuReportException;
import org.jeecg.modules.jmreport.common.util.JimuSpringContextUtils;
import org.jeecg.modules.jmreport.common.util.OkConvertUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 自定义积木报表鉴权(如果不进行自定义，则所有请求不做权限控制)
 * 1.自定义获取登录token
 * 2.自定义获取登录用户
 */
@Slf4j
@Component
public class JimuReportTokenServiceImpl implements JmReportTokenServiceI {
    @Autowired
    SecurityConfig securityConfig;
    
    /**
     * 通过请求获取Token
     * @param request
     * @return
     */
    @Override
    public String getToken(HttpServletRequest request) {
        String token = StpUtil.getTokenValue();
        log.debug("------SA--TOKEN-----RequestPath={} ，GET Token = {}", SaHolder.getRequest().getRequestPath(), token);
        if(StringUtils.isEmpty(token)){
            token = request.getParameter("token");
            // 将URL上的token设置到SaToken上下文，方便后续操作
            log.info("------SA--Init--TOKEN-----RequestPath={} ，从URL参数获取Token = {}", SaHolder.getRequest().getRequestPath(), token);
            StpUtil.setTokenValue(token);
        }
        return token;
    }

    /**
     * 通过Token获取登录人用户名
     * @param token
     * @return
     */
    @Override
    public String getUsername(String token) {
        String username = StpUtil.getLoginIdAsString();
        log.debug("------SA--TOKEN-----RequestPath={} ，Token={} , LoginId={}", SaHolder.getRequest().getRequestPath(), token, username);
        return username;
    }

    /**
     * 自定义用户拥有的角色
     *
     * @param token
     * @return
     */
    @Override
    public String[] getRoles(String token) {
        //积木内置三个角色 "admin","lowdeveloper","dbadeveloper"
        return new String[]{"admin","lowdeveloper","dbadeveloper"};
    }


    /**
     * 自定义用户拥有的权限指令
     * 
     * @param token
     * @return
     */
    @Override
    public String[] getPermissions(String token) {
        //drag:datasource:testConnection   仪表盘数据库连接测试
        //onl:drag:clear:recovery          清空回收站
        //drag:analysis:sql                SQL解析
        //drag:design:getTotalData         仪表盘对Online表单展示数据
        return new String[]{"drag:datasource:testConnection","onl:drag:clear:recovery","drag:analysis:sql","drag:design:getTotalData","onl:drag:page:delete"};
    }

    /**
     * Token校验
     * @param token
     * @return
     */
    @Override
    public Boolean verifyToken(String token) {
        try {
            if(securityConfig.getEnable()!=null && !securityConfig.getEnable()){
                // 如果security.enable=false,则不进行登录校验
                return true;
            }
            StpUtil.checkLogin();
            log.debug("--SaToken verifyToken-成功！RequestPath={}，Token = {}", SaHolder.getRequest().getRequestPath(), token);
        } catch (Exception e) {
            log.warn("Token校验失败: token = {}，error:{}", token, e.getMessage());
            
            if(e instanceof NotLoginException){
                // 跳转登录页面
                try {
                    if(!AjaxRequestUtils.isAjaxRequest(JimuSpringContextUtils.getHttpServletRequest())){
                        JimuSpringContextUtils.getHttpServletResponse().sendRedirect("/login/login.html");
                    }
                } catch (Exception ex) {
                }
                return false;
            }else{
                throw new JimuReportException(e);
            }
        }
        return true;
    }

//    /**
//     *  自定义请求头
//     * @return
//     */
//    @Override
//    public HttpHeaders customApiHeader() {
//        HttpHeaders header = new HttpHeaders();
//        header.add("custom-header1", "Please set a custom value 1");
//        header.add("token", "token value 2");
//        return header;
//    }

    /**
     * 自定义租户
     *
     * @return
     */
    @Override
    public String getTenantId() {
        String headerTenantId = null;
        HttpServletRequest request = JimuSpringContextUtils.getHttpServletRequest();
        if (request != null) {
            headerTenantId = request.getHeader(JmConst.HEADER_TENANT_KEY);
            if(OkConvertUtils.isEmpty(headerTenantId)){
                headerTenantId = request.getHeader(JmConst.HEADER_TENANT_ID);
            }
            if(OkConvertUtils.isEmpty(headerTenantId)){
                headerTenantId = request.getParameter(JmConst.TENANT_ID);
            }
        }
        return headerTenantId;
    }
}