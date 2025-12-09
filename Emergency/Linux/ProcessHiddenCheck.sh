#!/bin/bash
ls -alt /proc/ | awk '{print $NF}' | grep -E '[0-9]+' | grep -v '[A-Za-z]' > /tmp/process_list.check
ps aux | awk '{print $2}' | grep -v "PID" >> /tmp/process_list.check
cat /tmp/process_list.check | sort | uniq -c > /tmp/process_check.result
cat /tmp/process_check.result | grep -E '1 [0-9]+$' | awk '{print $2}' > /tmp/hidden_process.list


while IFS= read -r pid; do
    [[ $pid =~ ^[0-9]+$ ]] || continue       # 跳过非数字行
    [[ -e /proc/$pid/ ]] || continue  # 进程不存在则跳过
    printf 'Hiddened PID: %s ' "$pid"
    printf '\n'
done < /tmp/hidden_process.list

rm -rf /tmp/process_list.check
rm -rf /tmp/process_check.result
rm -rf /tmp/hidden_process.list
