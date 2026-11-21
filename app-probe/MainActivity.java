package com.coolapk.market;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Map;

/**
 * 最小验证 App —— 包名 com.coolapk.market
 *
 * 目的：验证数字联盟 SDK 是否只按「包名字符串」校验，
 *       而与 APK 签名 / 包体完整性无关。
 *
 * 做法：不编译期依赖 cn.shuzilm.core，全部走反射。
 *       classes.dex 是原版 shuzilm SDK dex，本类在 classes2.dex。
 */
public class MainActivity extends Activity {

    private static final String TAG = "DUID-PROBE";
    private TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (16 * getResources().getDisplayMetrics().density);
        ll.setPadding(p, p, p, p);
        tv = new TextView(this);
        tv.setTextSize(11);
        tv.setTextIsSelectable(true);
        ll.addView(tv);
        sv.addView(ll);
        setContentView(sv);

        log("package = " + getPackageName());
        log("version = " + safeVersion());
        log("");

        new Thread(new Runnable() {
            public void run() {
                runProbe();
            }
        }).start();
    }

    private String safeVersion() {
        try {
            Class<?> c = Class.forName("cn.shuzilm.core.Main");
            Method m = c.getMethod("getVersion");
            return String.valueOf(m.invoke(null));
        } catch (Throwable t) {
            return "SDK 加载失败: " + t;
        }
    }

    private void runProbe() {
        try {
            String apiKey = pickApiKey();
            log("apiKey = " + (apiKey == null ? "(未读到)" : apiKey.substring(0, Math.min(40, apiKey.length())) + "..."));
            log("");

            Class<?> mainCls = Class.forName("cn.shuzilm.core.Main");
            log("已找到 cn.shuzilm.core.Main");

            // 1) init(Context, String, boolean)
            Method init = mainCls.getMethod("init", Context.class, String.class, boolean.class);
            log("调用 init(context, apiKey, true)");
            init.invoke(null, this, apiKey, Boolean.TRUE);

            // 给 SDK 一点时间做异步初始化
            for (int i = 0; i < 20; i++) {
                Thread.sleep(500);
                String cached = readCached();
                if (cached != null && cached.length() > 4) {
                    log("");
                    log("★ 缓存已写入: " + cached);
                    break;
                }
            }

            // 2) getQueryID(Context, String, String, boolean) -> String
            log("");
            log("调用 getQueryID(context, \"\", \"\", true)");
            String id = null;
            try {
                Method gq = mainCls.getMethod("getQueryID", Context.class, String.class, String.class, boolean.class);
                Object r = gq.invoke(null, this, "", "", Boolean.TRUE);
                id = (String) r;
            } catch (Throwable t) {
                log("  该重载失败: " + t);
            }

            if (id == null || id.isEmpty()) {
                log("  返回空，换 Map 版本再试");
                try {
                    Class<?> helper = Class.forName("cn.shuzilm.core.DUHelper");
                    Method gq2 = helper.getMethod("getQueryID", Context.class, String.class, String.class, boolean.class);
                    Object r2 = gq2.invoke(null, this, "", "", Boolean.TRUE);
                    if (r2 instanceof Map) {
                        Map<?, ?> m = (Map<?, ?>) r2;
                        log("  Map 返回: " + m);
                        Object did = m.get("device_id");
                        if (did != null) id = String.valueOf(did);
                    }
                } catch (Throwable t) {
                    log("  Map 版本也失败: " + t);
                }
            }

            log("");
            if (id != null && !id.isEmpty() && !id.equals("null")) {
                log("★★★★★ 拿到 DUID: " + id);
                log("长度: " + id.length());
            } else {
                log("✗ 未拿到 DUID");
            }

            // 3) 看 SDK 自己缓存了什么
            String cached = readCached();
            log("");
            log("SharedPreferences 缓存 device_id = " + cached);

            log("");
            log("=== 完成 ===");
        } catch (Throwable t) {
            log("异常: " + t);
            StackTraceElement[] st = t.getStackTrace();
            for (int i = 0; i < Math.min(8, st.length); i++) {
                log("    at " + st[i]);
            }
            Log.e(TAG, "probe failed", t);
        }
    }

    /** 从 assets 读 config 里的原始 apiKey（RSA 公钥，非 init 所需的 42 字符 key） */
    private String readConfigKey() {
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                    getAssets().open("cn.shuzilm.config.json"), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            r.close();
            String s = sb.toString();
            int i = s.indexOf("\"apiKey\"");
            if (i < 0) return null;
            int a = s.indexOf('"', s.indexOf(':', i) + 1);
            int b = s.indexOf('"', a + 1);
            if (a < 0 || b < 0) return null;
            return s.substring(a + 1, b);
        } catch (Throwable t) {
            Log.e(TAG, "readConfig", t);
            return null;
        }
    }

    /**
     * 复刻 DUHelper.d(String) 的 apiKey 校验（反汇编实测）
     *   长度 42、以 "11" 开头、
     *   digit(charAt(2),16) == ((i3 + i4 + ((i5>>>17)^((i5>>>7)^i5) & 0xFF)) % 15) + 1
     *   其中 i6 从 2 到 len-1，i7 = i6-2，仅 1<=i7<=7 参与
     */
    private static boolean validApiKey(String s) {
        if (s == null || s.length() != 42) return false;
        if (s.charAt(0) != '1' || s.charAt(1) != '1') return false;
        int i3 = 0, i4 = 0, i5 = 0;
        for (int i6 = 2; i6 < s.length(); i6++) {
            char c = s.charAt(i6);
            int v;
            if (c >= '0' && c <= '9') v = c - 48;
            else if (c >= 'a' && c <= 'f') v = c - 87;
            else if (c >= 'A' && c <= 'F') v = c - 55;
            else return false;
            int i7 = i6 - 2;
            if (i7 >= 1 && i7 <= 7) {
                i5 = (i5 << 4) | v;
                i3 += Integer.bitCount(v);
                i4 += i7 * v;
            }
        }
        int calc = (((i3 + i4) + (((i5 >>> 17) ^ ((i5 >>> 7) ^ i5)) & 0xFF)) % 15) + 1;
        return Character.digit(s.charAt(2), 16) == calc;
    }

    /** 依次尝试候选 apiKey */
    private String pickApiKey() {
        String[] cands = new String[]{
            // 报文 75c 字段的值 —— 反汇编校验通过
            "11e7b222083a4b732b4b14811f6fc05995a01415eb",
            // 下面两个也通过校验，作为备选
            "1123010060355040813094775616e67646f6e67311",
            "11e301c06092a864886f70d010901160f6d6975694",
        };
        for (String c : cands) {
            if (validApiKey(c)) {
                log("候选通过校验: " + c);
                return c;
            }
        }
        log("所有候选都不合法");
        return cands[0];
    }

    private String readCached() {
        try {
            SharedPreferences sp = getSharedPreferences(getPackageName() + "_dna", 0);
            return sp.getString("device_id", null);
        } catch (Throwable t) {
            return null;
        }
    }

    private void log(final String s) {
        Log.i(TAG, s);
        runOnUiThread(new Runnable() {
            public void run() {
                tv.append(s + "\n");
            }
        });
    }
}
