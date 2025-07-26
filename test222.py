#业务逻辑如下
#主线程是ui界面，用户在其中输入一个消息aaaa，以及它要发送到的ip和端口
#这个消息被传递给队列区，发送线程察觉到发射队列非空，拿出一个元素来
#发送线程拿出来了ip和端口，以及消息，这将是一个三元组，首先它需要得到当前的时间戳，timeaaa
#然后结合一个“发送者的接收线程在那个端口”的信息，打包，编码，发送出去，这个线程还会立即收到一个送达的戳
#接收线程在开启后一直在趴着等消息，收到消息后立刻把消息解码成“在几点几分ipxxxx给我发来了消息xxxx”
#接收器还会立即反馈一个“好的我在几点几分收到了你的消息”
#这个消息会被放到队列区的另一个队列，这之后接收线程还会提醒队列区，队列区再去提醒ui线程，你的显示器该刷新了
#因此我们需要一个ui线程，它有
#一个显示大屏，显示所有的消息，这个显示大屏配一个端口配置区，带一个开关，以开启监听
#一个文字输入区，编辑输入消息，带一个ip，端口的框，这样用户可以编辑他的消息送到指定的位置
#一个队列区，他维护两个队列，第一个队列是发送队列，这个队列
import re
import socket
import queue
import threading
import time
import tkinter


class SendMsg(threading.Thread):
    """负责往外发的线程对象
    1. 创建时得到已有的队列区对象
    2. 等待队列区的工作信号，并从队列区得到一个对象，发送消息
    """
    def __init__(self, base_obj):
        super().__init__()
        #消息队列
        self.base_obj = base_obj
        self.message_queue = base_obj.queue_send
        # 创建一个新的socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        while True:
            #从队列里获取信息
            finall_msg = self.message_queue.get()
            if finall_msg == "exit":
                print("关闭发送线程")
                break
            #元组的前两个是地址和端口
            print("得到新的队列元素")
            target_ip = finall_msg[0]
            target_port = int(finall_msg[1])
            msg_time = finall_msg[2]
            msg_feedback_port = int(finall_msg[3])
            msg = finall_msg[4]
            #预处理发送串,时间戳####接收端口####真消息
            print("预处理发送数据包")
            send_msg = f"{msg_time}####{msg_feedback_port}####{msg}"
            #发送到指定的地点
            print("发送到指定的地点")
            self.client_socket.sendto(send_msg.encode(), (target_ip,target_port))

        #关闭socket
        print("关闭发送socket")
        self.client_socket.close()


class ReceivedMsg(threading.Thread):
    """负责接受的线程对象
    """
    def __init__(self, base_obj,port):
        super().__init__()
        self.base_obj = base_obj
        self.port = int(port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0.5)
        self.socket.bind(("0.0.0.0", self.port))
        # 可以启动了
        self.port_set_flag = True
        # 在输出窗口打印信息
        prompt_time = time.strftime("%H:%M:%S", time.localtime())
        prompt_info = f"{prompt_time}:监听线程绑定完成"
        self.base_obj.add_display_information(prompt_info)

    def over_listen(self):
        # 设置为未开启
        print("关闭接受线程")
        self.port_set_flag = False

    def run(self):
        while self.port_set_flag:
            try:
                #设置接受，这将会把这个线程阻滞在这一步
                #print("while self.port_set_flag:")
                data, client_address = self.socket.recvfrom(1024)
                #消息解码
                print("接收到新的数据包")
                data_info = data.decode()
                print(data_info)
                if not "已收到你的UDP消息000000" in data_info:
                    print("这是一个外来消息")
                    #按指定格式分割
                    data_splited = data_info.split("####")
                    #获得发送时间和真消息
                    data_send_time = data_splited[0]
                    data_send_fb_port = data_splited[1]
                    data_send_info = data_splited[2]
                    # # 预处理返回字符串，这会把一个新的发送对象放到等待发送的队列里
                    response_msg = "已收到你的UDP消息000000"
                    # # 发送时间戳
                    response_time = time.strftime("%H:%M:%S", time.localtime())
                    # # 自身的接受端口
                    response_feedback_port = self.port
                    # # 处理好的队列元素是一个元组
                    response_finall_msg = (client_address[0],data_send_fb_port,response_time,response_feedback_port,response_msg)
                    # # 置入发送队列
                    self.base_obj.queue_send.put(response_finall_msg)
                    # self.queue_send.put(finall_msg)
                    # # 启动发送（其实不需要）

                    # #预处理显示字符串
                    data_time = time.strftime("%H:%M:%S", time.localtime())
                    # 拼接好
                    finally_data = f"{data_time}:收到来自{client_address},{data_send_fb_port}于{data_send_time}发送的消息:{data_send_info}"
                    #调用接口展示
                    self.base_obj.add_display_information(finally_data)
                else:
                    #这代表收到的消息是对方的确认消息
                    print("这是一个送达回复消息")
                    # 按指定格式分割
                    data_splited = data_info.split("####")
                    # 获得发送时间和真消息
                    data_send_time = data_splited[0]
                    data_send_fb_port = data_splited[1]
                    data_send_info = data_splited[2]
                    # 预处理显示字符串
                    data_time = time.strftime("%H:%M:%S", time.localtime())
                    # 拼接好
                    finally_data = f"{data_time}:收到来自{client_address},{data_send_fb_port}于{data_send_time}发送的消息:{data_send_info}"
                    # 调用接口展示
                    self.base_obj.add_display_information(finally_data)

            except socket.timeout:
                #超时后重启循环
                continue

        print("关闭接受socket")
        self.socket.close()


class BaseUI:
    """负责主要的用户界面显示部分
    1. 初始化图形界面
    2. 创建队列区对象
    3. 创建发送线程，这个线程在收到发送请求前什么也不会干
    4. 创建接受线程，这个线程使用用户指定的接受端口
    5. 读取用户输入并传递给发送线程，但此前必须检查接受线程是否是开启的"""
    def __init__(self):
        #发送消息的队列
        self.queue_send = queue.Queue(maxsize=10)
        #上面是一个接受frame，这又分为配置frame和文本框frame，
        #  配置里面一个ent一个按钮，文本框里面一个text一个滑动条
        self.window1 = tkinter.Tk()
        self.window1.geometry("800x600")
        #接受区的框
        self.frame_receive = tkinter.LabelFrame(
            master=self.window1,
            text="接收区",
            bd=2,
            relief="raised")
        self.frame_receive.pack(side="top",fill="both",expand=True)
        #接受区的配置部分
        self.frame_r_set = tkinter.LabelFrame(
            master=self.frame_receive,
            text="配置监听器"
        )
        self.frame_r_set.pack(side="top",fill="both",expand=True)
        #接受区的设置部分，文本标签
        self.frame_r_s_label1 = tkinter.Label(master=self.frame_r_set,text="指定监听端口")
        self.frame_r_s_label1.pack(side="left",fill="x",expand=True)
        #输入端口的框
        self.listening_port = 8888
        self.frame_r_s_ent = tkinter.Entry(master=self.frame_r_set)
        self.frame_r_s_ent.insert(index=tkinter.END,string=str(self.listening_port))
        self.frame_r_s_ent.pack(side="left",fill="x",expand=True)
        #开启监听的按钮
        self.open_receive = tkinter.BooleanVar()
        self.open_receive.set(False)
        self.frame_r_s_button1 = tkinter.Checkbutton(
            master=self.frame_r_set,
            text="设定并开启监听端口",
            variable=self.open_receive,
            onvalue=True,
            offvalue=False,
            #command=lambda :print(self.open_receive.get())
            command=self._open_off_listening_thread,
        )
        self.frame_r_s_button1.pack(side="left",fill="x",expand=True)
        #接受区的显示部分
        self.frame_r_put_scrollbar = tkinter.Scrollbar(master=self.frame_receive)
        self.frame_r_put_scrollbar.pack(side="right", fill="y", expand=False)
        self.frame_r_put = tkinter.Text(
            master=self.frame_receive,
            yscrollcommand=self.frame_r_put_scrollbar.set
        )
        #默认情况下，这个框的输入被关闭，只有下面那个修改函数可以临时改动这个框的内容，然后再被关闭
        self.frame_r_put.config(state="disabled")
        self.frame_r_put.pack(side="left",fill="both",expand=True)
        self.frame_r_put_scrollbar.config(command=self.frame_r_put.yview)

        #发送区
        self.frame_send = tkinter.LabelFrame(
            master=self.window1,
            text="发送区",
            bd=2,
            relief="raised")
        self.frame_send.pack(side="bottom",fill="both",expand=True)
        #发送地址的部分
        self.frame_s_set = tkinter.LabelFrame(
            master=self.frame_send,
            text="配置发送地址"
        )
        self.frame_s_set.pack(side="top",fill="both",expand=True)
        #文本标签，框，文本标签，框，按钮
        self.frame_s_s_label1 = tkinter.Label(master=self.frame_s_set,text="目标地址")
        self.frame_s_s_label1.pack(side="left", fill="x", expand=True)
        #用户往里输入目标ip的框，默认输入是本机
        self.frame_s_s_IPent = tkinter.Entry(master=self.frame_s_set)
        self.frame_s_s_IPent.pack(side="left", fill="x", expand=True)
        self.frame_s_s_IPent.insert(index=tkinter.END, string="127.0.0.1")

        self.frame_s_s_label2 = tkinter.Label(master=self.frame_s_set,text="目标端口")
        self.frame_s_s_label2.pack(side="left", fill="x", expand=True)
        #类似的，默认8888
        self.frame_s_s_PORTent = tkinter.Entry(master=self.frame_s_set)
        self.frame_s_s_PORTent.pack(side="left", fill="x", expand=True)
        self.frame_s_s_PORTent.insert(index=tkinter.END, string="8888")
        #纯粹的分隔符
        self.frame_s_s_label3 = tkinter.Label(master=self.frame_s_set, text="    ")
        self.frame_s_s_label3.pack(side="left", fill="x", expand=True)
        self.frame_s_s_button = tkinter.Button(
            master=self.frame_s_set,
            text="点我发送到目标位置",
            #command=lambda :print("set!")
            command=self._send_2_specified_location
        )
        self.frame_s_s_button.pack(side="left", fill="x", expand=True)
        #下半部分是一个滚动条+文本框
        self.frame_send_put_scrollbar = tkinter.Scrollbar(master=self.frame_send)
        self.frame_send_put_scrollbar.pack(side="right", fill="y", expand=False)
        self.frame_send_put = tkinter.Text(
            master=self.frame_send,
            yscrollcommand=self.frame_send_put_scrollbar.set
        )
        self.frame_send_put.pack(side="left", fill="both", expand=True)
        self.frame_send_put_scrollbar.config(command=self.frame_send_put.yview)

        #线程交互部分
        self.send_T = SendMsg(base_obj=self)
        self.send_T.start()     #直接启动
        self.receive_T = None  #等下设定完了再创建

        # 设置关闭事件处理
        self.window1.protocol("WM_DELETE_WINDOW", self.on_close)


    def validate_ip(self,ip_str):
        """验证IP地址是否合法"""
        # IP地址验证正则表达式
        print("验证IP地址是否合法")
        ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(ip_pattern, ip_str))

    def validate_port(self,port_str):
        """验证端口号是否合法"""
        # 端口号验证正则表达式
        print("验证端口号是否合法")
        port_pattern = r"^([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$|^0$"
        return bool(re.match(port_pattern, port_str))

    def on_close(self,event=None):
        #优雅的关闭子线程
        print("优雅的关闭子线程")
        print("关闭发送线程")
        self.queue_send.put("exit")
        self.send_T.join()
        if not self.receive_T is None:
            print("关闭接收线程")
            self.receive_T.over_listen()
            self.receive_T.join()
        print("关闭窗口")
        self.window1.destroy()  # 关闭窗口

    def _open_off_listening_thread(self, event=None):
        print("设置监听线程的开与关")
        print(self.open_receive.get())
        # 若Checkbutton所设置的按钮值为真，这代表将要启动监听线程
        if self.open_receive.get():
            print("重新设置bind端口并开启监听线程")
            # 从设置框里得到数据
            set_port = self.frame_r_s_ent.get()
            self.listening_port = set_port
            if self.validate_port(set_port):
                # 若接受线程已经启动，则先关闭它
                print("新设置的端口是一个合法的值")
                if not self.receive_T is None :
                    print("监听线程正在运行，先关闭")
                    self.receive_T.over_listen()
                    self.receive_T.join()

                # 重新创建线程实例
                print("重新创建监听线程对象")
                self.receive_T = ReceivedMsg(self,port=set_port)
                # 设置监听线程
                # 启动接受线程，进行监听
                self.receive_T.start()

                # 记录日志
                start_time = time.strftime("%H:%M:%S", time.localtime())
                info = f"{start_time}:监听线程已启动，端口:{set_port}"
                self.add_display_information(info)

            else:  # 输入了非法的端口
                print("新设置的端口是非法的")
                error_time = time.strftime("%H:%M:%S", time.localtime())
                info = f"{error_time}:非法的端口值"
                self.add_display_information(info)

        else:  # 反之，则需要关闭监听
            print("关闭监听线程")
            if not self.receive_T is None:  #若线程已启动
                print("监听线程已启动，正在关闭并收回线程")
                # 关闭监听
                self.receive_T.over_listen()
                # 收回线程
                self.receive_T.join()
                # 记录日志
                stop_time = time.strftime("%H:%M:%S", time.localtime())
                info = f"{stop_time}:监听线程已停止"
                self.add_display_information(info)
            else:
                print("监听线程未启动，不需要操作")
                #线程未启动直接打印即可
                stop_time = time.strftime("%H:%M:%S", time.localtime())
                info = f"{stop_time}:不需关闭，监听线程不存在"
                self.add_display_information(info)

    def _send_2_specified_location(self,event=None):
        print("尝试发送到指定的位置")
        #检验有没有开启监听，若未开启，则不许发送
        if not self.receive_T is None:
            print("监听线程开启中，可以发送")
            #预编辑输入信息
            #目标地址
            target_ip = self.frame_s_s_IPent.get()
            #目标端口
            target_port = self.frame_s_s_PORTent.get()
            print("校验ip和port输入是否合法")
            if self.validate_ip(target_ip) and self.validate_port(target_port):
                #从框中得到信息
                print("预处理发送信息包")
                msg = self.frame_send_put.get("1.0", "end-1c")
                #发送时间戳
                msg_time = time.strftime("%H:%M:%S", time.localtime())
                #自身的接受端口
                msg_feedback_port = self.listening_port
                #处理好的队列元素是一个元组
                finall_msg = (target_ip,target_port,msg_time,msg_feedback_port,msg)
                # 置入发送队列
                print("置入发送队列")
                self.queue_send.put(finall_msg)
                #启动发送（其实不需要）
            else:
                # 不合法的ip或端口
                print("ip或port不合法")
                error_time = time.strftime("%H:%M:%S", time.localtime())
                info = f"{error_time}:ip或port不合法"
                self.add_display_information(info)
        else:
            #没开启监听就拒绝发送
            print("监听端口未启动，不能发送")
            error_time = time.strftime("%H:%M:%S", time.localtime())
            info = f"{error_time}:监听线程未启动，必须在监听启动后发送"
            self.add_display_information(info)

    def add_display_information(self,info):
        #在显示区域展示预处理好的字符串
        print("刷新消息显示区域")
        self.frame_r_put.config(state="normal")
        self.frame_r_put.insert(index=tkinter.END, chars="\n")  #先打印一个换行
        self.frame_r_put.insert(index=tkinter.END,chars=info)
        self.frame_r_put.config(state="disabled")

    def run(self):
        self.window1.mainloop()



if __name__ == "__main__":
    base = BaseUI()
    base.run()
