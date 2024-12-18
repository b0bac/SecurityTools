import sys
import datetime
import chinese_calendar as calendar


banner = """
######################################################################################
#         欢迎使用       XXXXXXXXXXXXXXXXXXXXXX      节假日值班自动排班程序V2.0         #
#                                作者：b0b@c                                          #
#                            支持福利假期设定                                          #
######################################################################################
"""
worker_list= [] # worker_list = 
holiday_dict = {
    "New Year's Day":"元旦假期",
    "Spring Festival":"春节假期",
    "Tomb-sweeping Day":"清明假期",
    "Labour Day": "五一假期",
    "Dragon Boat Festival": "端午假期",
    "Mid-autumn Festival": "中秋假期",
    "National Day": "国庆假期",
    "5":"周六休假",
    "6":"周日休假"
}
qax_holidays= []

def set_qax_holidays(day_string):
    global qax_holidays
    try:    
        year = int(day_string.split("-")[0])
        month = int(day_string.split("-")[1])
        day=int(day_string.split("-")[2])
        qax_holidays.append((datetime.date(year, month, day),"福利休假"))
        return True
    except Exception as error:
        return False

def get_holiday_name(day):
    name = calendar.get_holiday_detail(day)[1] 
    name = name if name is not None else str(day.weekday())
    return holiday_dict[name]

def get_holidays(year):
    global qax_holidays
    qax_holidays = list(set(qax_holidays))
    holidays = [] 
    holiday_list = calendar.get_holidays(start=datetime.date(year,1,1), end=datetime.date(year,12,31))
    for day in holiday_list:
        holidays.append((day, get_holiday_name(day)))
    holidays.extend(qax_holidays)
    holidays.sort()
    return holidays
    
def work_schedule(year):
    holidays = get_holidays(year)
    with open("%s_OnDuty_Table.csv" % str(year), 'w') as file_writer:
        file_writer.writelines("值班日期,假期名称,值班方式,值班人\n")
        for index, holiday in enumerate(holidays):
            day_date = str(holiday[0])
            day_name = holiday[1]
            work_style = "公司值班" if holiday[1] in ["周六休假", "周日休假"] else "远程值班"
            worker_index = index % 7
            worker_name = worker_list[worker_index]
            stuff = "%s,%s,%s,%s\n" % (day_date, day_name, work_style, worker_name)
            file_writer.writelines(stuff)


if __name__ == "__main__":
    year = 2025
    print(banner)
    try:
        year = int(sys.argv[1])
    except Exception as error:
        print("[-] 您输入的年份错误或官方尚未给出法定假期安排")
        sys.exit(0)
    while(True):
        day = input("[*] 请输入福利假日安排（按天输入一次一天），例如2025-02-06，不再继续请输入0:")
        if day == "0":
            break
        result = set_qax_holidays(day)
        if not result:
            print("[-] 输入错误，请重新输入")
        else:
            print("[+] 已添加，请输入下一天:")
    while(True):
        workers = input("[*] 请输入排班人员（姓名编号，逗号分割），例如 xx23,xx02,xxxx,...:")
        try:
            worker_list = workers.split(",")
            worker_list = list(set(worker_list))
            try:
                worker_list.remove("")
            except Exception as error:
                pass
            break
        except Exception as error:
            print("[-] 输入错误，请重新输入")
            continue
    try:
        work_schedule(year)
        print("[+] 排班完成，请在本目录下查看%s_OnDuty_Table.csv文件" % str(year))
    except Exception as error:
        print("[-] 发生错误： %s" %str(error))
        
