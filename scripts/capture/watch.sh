#!/system/bin/sh
# watch.sh — ★ 设备端进程守望（消除 adb 往返延迟）
#
# 依据 DEVICE_LESSONS_AND_SHORT_LIVED_PROC.md §七 方向 A：
#   「设备端 shell 循环：发现新进程就立刻处理 / 把 pid 写到固定文件，Python 读文件
#     （无 adb 往返）」
#
# ★ 关键：用【精确匹配 cmdline 第一个 token】，
#   避免 Coolapk 频繁执行 content 命令导致的误报上百个 pid
#   （DEVICE_LESSONS §三 记录过这个坑）

PKG="com.coolapk.market"
SEEN=/data/local/tmp/.seen_pids
: > "$SEEN"

# ★ 启动快照：把【已经存在】的进程也报出来（避免错过启动早的主进程）
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ -r "$d/cmdline" ] || continue
    n=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -1)
    case "$n" in
        "$PKG"|"$PKG":*)
            echo "$p" >> "$SEEN"
            echo "EXIST $p $n"
            ;;
    esac
done

echo "WATCH_READY"

while true; do
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ -r "$d/cmdline" ] || continue
        n=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -1)
        case "$n" in
            "$PKG"|"$PKG":*)
                if ! grep -q "^$p\$" "$SEEN" 2>/dev/null; then
                    echo "$p" >> "$SEEN"
                    echo "NEW $p $n"
                fi
                ;;
        esac
    done
    # 设备端 30ms 轮询 —— 比 adb 往返（~80ms）快，且不产生网络开销
    sleep 0.03 2>/dev/null || sleep 1
done
