package javax.servlet.http;

import javax.servlet.*;
import java.util.*;

public interface HttpSession
{
    long getCreationTime();

    String getId();

    long getLastAccessedTime();

    ServletContext getServletContext();

    void setMaxInactiveInterval(final int p0);

    int getMaxInactiveInterval();

    @Deprecated
    HttpSessionContext getSessionContext();

    Object getAttribute(final String p0);

    @Deprecated
    Object getValue(final String p0);

    Enumeration<String> getAttributeNames();

    @Deprecated
    String[] getValueNames();

    void setAttribute(String attNamr, Object attVal);

    @Deprecated
    void putValue(String key,Object val);

    void removeAttribute(String val);

    @Deprecated
    void removeValue(String key);

    void invalidate();

    boolean isNew();

    class HttpSessionContext {
    }

    class ServletContext {
    }
}
