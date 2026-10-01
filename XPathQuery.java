/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;

import org.w3c.dom.Document;
/**
 *
 * @author breakthesec
 */
public class XPathQuery extends HttpServlet {



    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try {
            String user=request.getParameter("username");
            String pass=request.getParameter("password");

            //XML Source:
            String XML_SOURCE=getServletContext().getRealPath("/WEB-INF/users.xml");

            //Parsing XML:
            DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder=factory.newDocumentBuilder();
            Document xDoc=builder.parse(XML_SOURCE);

            XPath xPath=XPathFactory.newInstance().newXPath();

            // Use XPathVariableResolver to pass user input as typed variables,
            // preventing XPath injection and ensuring the value stored in the
            // session is derived from trusted XML data, not user-controlled syntax.
            final Map<String, String> vars = new HashMap<String, String>();
            vars.put("username", user != null ? user : "");
            vars.put("password", pass != null ? pass : "");
            xPath.setXPathVariableResolver(new XPathVariableResolver() {
                public Object resolveVariable(QName variableName) {
                    return vars.get(variableName.getLocalPart());
                }
            });

            //XPath Query using parameterized variables (no string concatenation):
            String xPression="/users/user[username=$username and password=$password]/name";

            //running Xpath query:
            String name=xPath.compile(xPression).evaluate(xDoc);
            out.println(name);
            if(name.isEmpty())
            {
                response.sendRedirect(response.encodeURL("ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
            }
            else
            {
                 HttpSession session=request.getSession();
                 session.setAttribute("isLoggedIn", "1");
                 // name is now sourced from trusted XML data via parameterized XPath,
                 // not from user-controlled input.
                 session.setAttribute("user", name);
                 response.sendRedirect(response.encodeURL("ForwardMe?location=/index.jsp"));
            }
        }
        catch(Exception e)
        {
            out.print(e);
        }
        finally {
            out.close();
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
