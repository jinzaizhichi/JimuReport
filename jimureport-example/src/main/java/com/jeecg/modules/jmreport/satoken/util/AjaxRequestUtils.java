package com.jeecg.modules.jmreport.satoken.util;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.session.SaSession;
import com.alibaba.fastjson.JSON;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
public class AjaxRequestUtils {
    
    /**
     * 判断是否为 AJAX 请求
     */
    public static boolean isAjaxRequest(HttpServletRequest request) {
        // 1. 检查 X-Requested-With 头部
        String xRequestedWith = request.getHeader("X-Requested-With");
        if ("XMLHttpRequest".equalsIgnoreCase(xRequestedWith)) {
            return true;
        }
        
        // 2. 检查 Accept 头部
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            return true;
        }
        
        // 3. 检查 Content-Type 头部（对于 POST 请求）
        String contentType = request.getHeader("Content-Type");
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        
        // 4. 检查请求参数（某些框架会添加特定参数）
        String ajaxParam = request.getParameter("_ajax");
        if ("true".equals(ajaxParam)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 根据请求类型返回相应响应
     */
    public static void writeResponse(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   Object data) throws IOException {
        
        if (isAjaxRequest(request)) {
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(JSON.toJSONString(data));
        } else {
            // 普通请求处理
            request.setAttribute("data", data);
            // 这里可以转发到相应的 JSP 页面
        }
    }

    /**
     * 设置 Sa-Token 会话的登录来源和拖拽开关
     */
    // 登录来源-积木报表示例
    public final static String LOGIN_FROM_MODEL_NEED_LOGOUT = "jimu_example";

    public static void setLoginSessionInfo() {
        HttpSession originalSession = ((HttpServletRequest) SaHolder.getRequest().getSource()).getSession();
        if (originalSession!=null && originalSession.getAttribute("loginFrom") == null) {
            log.info("设置登录来源，BI与报表切换开关，注入个性化session信息。");
            originalSession.setAttribute("loginFrom", LOGIN_FROM_MODEL_NEED_LOGOUT);
            originalSession.setAttribute("switchJimuDrag", true);
        }
    }
    
}