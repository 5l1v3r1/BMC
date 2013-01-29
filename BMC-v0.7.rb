#!/usr/bin/ruby
=begin



#--> Required gems
gem install virustotalapi  rest-client mechanize  html-table
=end

gems = %w{rubygems net/http net/https net/smtp json virustotalapi rest-client mechanize html/table} ; gems.each  {|gem| require gem}
include HTML
#require 'rubygems'
#require 'net/http'
#require 'net/https'
#require 'net/smtp'
#require 'json'
#require 'virustotalapi'
#require 'rest-client'
#require 'mechanize'
#require 'html/table'


Dir.mkdir("files_store" , 1775) if Dir.exist?("files_store") == false
APP_ROOT     = Dir.pwd
FILES_STORE  = "#{APP_ROOT}/files_store/"
API_KEY      = '67168ef6c99aba5fad9a0e364db3b359dcf62a7feef3f22c491c98824fc0cc6d'            # Put your VT API here
DB_URL       = "http://localhost/m3.txt"                 # Put your URL here
$log         = "bmc.log"


class Downloader

    def initialize
        @agent                          = Mechanize.new
        @agent.pluggable_parser.xml     = Mechanize::Download
        @agent.pluggable_parser.default = Mechanize::Download
        @agent.max_file_buffer          = 5          # Don't load file to memory
        @agent.max_history              = 0
    end

    def alive?(url)
        uri          = URI.parse(url)
        http         = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true if uri.scheme == 'https'
        response     = http.head(uri.path).code.to_i

        if response == 200
            return true
        else
            return false
        end

    end

    def download (url , path = FILES_STORE)
        begin
            if alive?(url) == true
                file     = File.basename(url)
                File.rename("#{path}/#{file}" , "#{path}/#{file}.#{Random.rand(1...100)}") if File.exist?("#{path}/#{file}")
                get_file = @agent.get(url)
                get_file.save("#{path}/#{file}")
                return File.absolute_path(file)
            end
        rescue
            File.open($log , "a+") {|log| log.puts "[#{Time.now}]} - #{url} 404 - HTTP Not Found"}
        end

    end
end


class Info
        attr_reader   :list
        #attr_accessor :parse

        def initialize(parse)
            @parse        = parse
            @tmp_grep     = ".grep.txt"
            @tmp_awk      = ".awk.txt"
            File.delete(@tmp_grep)  if File.exist?(@tmp_grep) == true
            File.delete(@tmp_awk)   if File.exist?(@tmp_awk)  == true
        end

        def check_file(file)
            case
                when File.exist?(file) == false
                    File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{File.absolute_path(file)} Not Found"}
                    puts "[#{Time.now}]} - #{File.absolute_path(file)} Not Found"
                    exit
                when File.readable?(file) == false
                    File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{File.absolute_path(file)} Unreadable, check file permissions!"}
                    puts "[#{Time.now}]} - #{File.absolute_path(file)} Unreadable, check file permissions!"
                    exit
                when File.writable?(file) == false
                    File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{File.absolute_path(file)} Un-writable , check file permissions!"}
                    puts "[#{Time.now}]} - #{File.absolute_path(file)} Unwritable , check file permissions!"
                    exit
                when nil? == true
                    File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{File.absolute_path(file)} nil nil nil!"}
                    puts "[#{Time.now}]} - #{File.absolute_path(file)} nil nil nil!!"
                    exit
                else
                    File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{File.absolute_path(file)} Something else wrong!"}
                    puts "[#{Time.now}]} - #{File.absolute_path(file)} Something else wrong!!"
                    exit
            end
        end

        def grep(downloaded_file = @parse)
            begin
                File.open(downloaded_file , "r") do |file|
                    file.each_line do |line|
                        File.open(@tmp_grep , "a+") do |grep|
                            grep.puts line if line.include?("http") || line.include?("https")     # grep lines has http(stop2list) only
                        end
                    end
                end
            rescue
                check_file(downloaded_file)
            end

            return @tmp_grep
        end

        def awk(grepped = @tmp_grep)
            begin
                grep_ary = IO.readlines(grepped)
                grep_ary.each do |column|
                    File.open(@tmp_awk , "a+") do |stop2list|
                        stop2list.puts "#{column.split(" ")[2]}:#{column.split(" ")[6]}"                # Write stop2list of format(IP:URL) in .awk.txt
                    end
                end
            rescue
                check_file(grepped)
            end

            return @tmp_awk
        end

        def list
            grep
            awk
            begin
                list_db = []
                File.open(@tmp_awk).each do |l|
                    list_2_hash = {"#{l.split(":", 0)[0]}" => "#{l.split(":",2)[1]}".chomp}         # {ip:url}
                    list_db << list_2_hash                                                          # [{ip1:url1} , {ip2:url2}]
                end
            rescue
                check_file(@tmp_awk)
            end
            return list_db                  #  [{ip1=>url1} , {ip2=>url2}]
        end

end


class AntiVirus < VirusTotal::API

    # Its small modification on VirusTotal::API to use APIv2 instead of APIv1
    GET_FILE_REPORT = 'https://www.virustotal.com/vtapi/v2/file/report.json'
    SCAN_FILE       = 'https://www.virustotal.com/vtapi/v2/file/scan.json'

end


class Alert

    def initialize

        @smtp_server  = "localhost"                                             # Put your smtp server here
        @port         = 25                                                      # SMTP port
        @from_email   = "ssaleh@advancedoperations.com"                       	# Sender e-mail
        #@from_email   = "malwarealert@security4arabs.net"                       # Sender e-mail
        @to_email     = "sabri@security4arabs.net"                              # Receiver e-mail
        @cc           = "king.sabri@gmail.com"                                  # Comment this line if there is no Cc
        @subject      = "Malware alert! - #{Time.new.strftime("%d-%m-%Y")}"     # e-mail's Subject - date
        @mime         = "MIME-Version: 1.0"
        @content_type = "Content-type: text/html"
    end

    def message(full_result)                 # << [[ip1,file1,url1,hash1,report1,cleanness1],[ip2,file2,url2,hash2,report2,cleanness2]]
                                             #    [[ 0 , 1   , 2  ,  3  ,   4   ,    5     ]]
        ip_address     = ""
        file_name      = ""
        result         = ""
        url            = ""
        date           = Time.new.strftime("%d-%m-%Y")
        table_contents = [["<strong>IP-address</strong>" ,
                           "<strong>File name</strong>"  ,
                           "<strong>URL</strong>"        ,
                           "<strong>Result</strong>"     ,
                           "<strong>Date</strong>"]]

        full_result.each do |res|
            ip_address = res[0]
            file_name  = res[1]
            result     = res[2]
            url        = res[5]
            table_contents << [ip_address , file_name , result , url , date]
        end
        table = Table.new(table_contents)
        table.border     = 1
        table[0].align   = "CENTER"
        table[0].colspan = 2
        body             = table.html

        return body
    end

    def send_mail(message)
        Net::SMTP.start(@smtp_server, @port) do |smtp|
              smtp.set_debug_output $stderr
              smtp.open_message_stream(@from_email, @to_email) do |f|
                    f.puts "From: #{@from_email}"
                    f.puts "To: #{@to_email}"
                    f.puts "Cc: #{@cc}"                                 # Commend this line if there is no Cc
                    f.puts "Subject: #{@subject}"
                    f.puts @mime
                    f.puts @content_type
                    f.puts "#{message}"
                  end
            end
    end

end




class BasharMalwareCheker


    def initialize
        @wget = Downloader.new
        @info = Info.new(@wget.download(DB_URL , APP_ROOT))
        @list = @info.list                      # [{ip1 => url1} , {ip2 => url2}]
        @av   = AntiVirus.new(API_KEY)
    end


    def scan (list = @list)                     # << [{ip1 => url1} , {ip2 => url2}]
        file_counter = 0
        @@scanned_files_ip    = []
        @@scanned_files_list  = []
        @@scanned_files_url   = []
        @@scanned_files_hash  = []
        scanned_with_id       = []

        list.each do |hash|
            ip        = hash.keys
            file_url  = hash.values
            file_name = File.basename(file_url[0])
            @wget.download(file_url[0])
            next if File.exist?("#{FILES_STORE}#{file_name}") == false        # TODO Handle file if not exsit
            if File.size("#{FILES_STORE}#{file_name}") > 33554432             # check, delete & log  file if size > (33554432 = 32MB) VT policy :)
                File.delete("#{FILES_STORE}#{file_name}")
                File.open($log , "a+") {|log| log.puts "[#{Time.now}] - #{file_url} file is bigger than 32MB. File deleted"}
            end

            file_counter += 1 if file_counter < 4
            scan_hash = @av.scan_file("#{FILES_STORE}#{file_name}")

            @@scanned_files_ip   << ip[0]
            @@scanned_files_list << file_name
            @@scanned_files_url  << file_url[0]
            @@scanned_files_hash << scan_hash

            scanned_with_id    << {file_name => scan_hash}

            if file_counter >= 4
                file_counter = 0
                sleep 60
            end
        end
           return scanned_with_id          # [{file1.exe => scan_hash1} , {file2.exe => scan_hash2}]
    end


    def report(scan_hash_list)               # << [{file1.exe => scan_hash1} , {file2.exe => scan_hash2}]
        @@report         = []
        file_with_report = []
        scan_hash_list.each do |scan_hash|
            file         = scan_hash.keys[0]
            hash         = scan_hash.values[0]
            file_report  = @av.get_file_report(hash)
            @@report         << file_report[1]                    # block in report': undefined method `[]' for nil:NilClass (NoMethodError)
            file_with_report << {file => file_report[1]}
        end
        return file_with_report                       # [{file1.exe => report1} , {file2.exe => report2}]
    end


    def clean_file?(report)                # << [{file1.exe => report1} , {file2.exe => report2}]
        @@cleanness   = []
        clean_counter = 0
        report.each do |result|
            result.each do |(file,result_hash)|
                result_hash.each_with_index do |(av , result) , i|
                            clean_counter += 1 if result.chr.empty? == false           # Counter for number of AV detects the file
                            if (result_hash.size - 1) == i                             # Last element ?
                                    case
                                        when clean_counter >= 5
                                            @@cleanness << "Infected!"
                                        when clean_counter < 5
                                            @@cleanness << "Clean!"
                                        else
                                            @@cleanness << clean_counter
                                    end
                                    clean_counter = 0
                            end
                        end
                end
        end
    end


    def result                                      # << [[ip1,file1,url1,hash1,report1,cleanness1],[ip2,file2,url2,hash2,report2,cleanness2]]
        result =
            @@scanned_files_ip.zip(@@scanned_files_list       ,
                                         @@scanned_files_url  ,
                                         @@scanned_files_hash ,
                                         @@report             ,
                                         @@cleanness)

        File.open("scan-result_#{Time.now.strftime("%d-%m-%Y")}.txt" , 'a+') {|r| r.puts result}
        return result                              # [[ip1,file1,url1,hash1,report1,cleanness1],[ip2,file2,url2,hash2,report2,cleanness2]]
    end

end


# TODO check if malware db file is empty
# TODO check if malware db file is exsit :)
# TODO check if malware is exist in files_store or not
# TODO check if malware url is valid
bashar = BasharMalwareCheker.new
scan   = bashar.scan
report = bashar.report(scan)
clean  = bashar.clean_file?(report)
result = bashar.result

alert = Alert.new
msg   = alert.message(result)
alert.send_mail(msg)










=begin
[
    ["71.21.92.219", "uTorrent.exe", "http://download.utorrent.com/3.2/uTorrent.exe",
     "b9e25caed9b30bdb2863dd62e0860b8a77de87a4ee6b70d7265b00bcc5603055-1344986057",
     {"nProtect"=>"", "CAT-QuickHeal"=>"", "McAfee"=>"", "K7AntiVirus"=>"", "TheHacker"=>"", "VirusBuster"=>"", "F-Prot"=>"",
      "Symantec"=>"", "Norman"=>"", "TotalDefense"=>"", "TrendMicro-HouseCall"=>"", "Avast"=>"", "eSafe"=>"", "ClamAV"=>"",
      "BitDefender"=>"", "SUPERAntiSpyware"=>"", "ByteHero"=>"", "Emsisoft"=>"", "Comodo"=>"", "F-Secure"=>"", "DrWeb"=>"",
      "VIPRE"=>"", "AntiVir"=>"", "TrendMicro"=>"", "McAfee-GW-Edition"=>"", "Sophos"=>"", "Jiangmin"=>"", "Antiy-AVL"=>"",
      "Microsoft"=>"", "ViRobot"=>"", "GData"=>"", "Commtouch"=>"", "AhnLab-V3"=>"", "VBA32"=>"", "PCTools"=>"", "ESET-NOD32"=>"",
      "Rising"=>"", "Ikarus"=>"", "Fortinet"=>"", "AVG"=>"", "Panda"=>""}, "true"],

    ["72.21.92.239", "installer_download_toolbar.exe", "http://download.phpnuke.org/o/en/92375/installer_download_toolbar.exe",
     "ee8628c26ae6925ba5a2b96e227893920f0156f3d34a73bb6453aff9ac2953e5-1344986067",
     {"nProtect"=>"", "CAT-QuickHeal"=>"", "McAfee"=>"", "K7AntiVirus"=>"", "TheHacker"=>"", "VirusBuster"=>"", "F-Prot"=>"", "Symantec"=>"",
      "Norman"=>"W32/Zugo.DSUM", "TotalDefense"=>"", "TrendMicro-HouseCall"=>"TROJ_GEN.F47V0812", "Avast"=>"", "eSafe"=>"", "ClamAV"=>"",
      "Kaspersky"=>"", "BitDefender"=>"", "SUPERAntiSpyware"=>"", "Emsisoft"=>"", "Comodo"=>"", "F-Secure"=>"", "DrWeb"=>"Adware.Downware.174",
      "VIPRE"=>"", "AntiVir"=>"ADWARE/Adware.Gen2", "TrendMicro"=>"", "McAfee-GW-Edition"=>"", "Sophos"=>"", "Jiangmin"=>"", "Antiy-AVL"=>"",
      "Microsoft"=>"", "ViRobot"=>"", "AhnLab-V3"=>"", "GData"=>"", "Commtouch"=>"", "ByteHero"=>"", "VBA32"=>"", "PCTools"=>"",
      "ESET-NOD32"=>"Win32/Toggle", "Rising"=>"AdWare.Script.Toolbar.a", "Ikarus"=>"", "Fortinet"=>"W32/Toggle", "AVG"=>"", "Panda"=>""}, "false"],

    ["71.21.92.219", "Bifrost.exe", "http://localhost/Bifrost.exe",
     "c90185435587a92af5c58a6dda7e64e13c55adcd71b9426474fc716405de8c18-1344986092",
     {"nProtect"=>"Backdoor/W32.Bifrose.1843200", "CAT-QuickHeal"=>"Backdoor.Bifrose.bwt.n8", "McAfee"=>"Generic.gm", "K7AntiVirus"=>"Backdoor",
      "TheHacker"=>"Backdoor/Bifrose.bwt", "VirusBuster"=>"Backdoor.Bifrose!ZVIILMTza8I", "F-Prot"=>"W32/Backdoor2.FCKA", "Symantec"=>"Backdoor.Bifrose",
      "Norman"=>"W32/Bifrose.B!genr", "TotalDefense"=>"Win32/Bifrost!generic", "TrendMicro-HouseCall"=>"BKDR_BIFROSE.MIC", "Avast"=>"Win32:Bifrose-EUK [Trj]",
      "eSafe"=>"Win32.Banker", "ClamAV"=>"", "Kaspersky"=>"Backdoor.Win32.Bifrose.afe", "BitDefender"=>"Backdoor.Generic.418706",
      "ViRobot"=>"Backdoor.Win32.Bifrose.1843200", "ByteHero"=>"", "Sophos"=>"Troj/Agent-JZZ", "Comodo"=>"Backdoor.Win32.Bifrose.ADR",
      "F-Secure"=>"Backdoor.Generic.418706", "DrWeb"=>"BackDoor.Bifrost.57", "VIPRE"=>"Backdoor.Win32.Bifrose (fs)", "AntiVir"=>"BDS/Agent.BKY",
      "TrendMicro"=>"BKDR_BIFROSE.MIC", "McAfee-GW-Edition"=>"Artemis!A17F40D3882F", "Emsisoft"=>"Virus.Win32.Bifrose!IK",
      "Jiangmin"=>"Backdoor/Bifrose.ucw", "Antiy-AVL"=>"", "Microsoft"=>"Backdoor:Win32/Bifrose.gen!B", "SUPERAntiSpyware"=>"Heur.Agent/Gen-Bifrost",
      "GData"=>"Backdoor.Generic.418706", "Commtouch"=>"W32/Backdoor2.FCKA", "AhnLab-V3"=>"Win-Spyware/Bifrose.1843200", "VBA32"=>"Backdoor.Win32.Bifrose.bwt",
      "PCTools"=>"Backdoor.Bifrose", "ESET-NOD32"=>"Win32/Bifrose.ADR", "Rising"=>"Backdoor.Win32.Bifrose.afe", "Ikarus"=>"Virus.Win32.Bifrose",
      "Fortinet"=>"W32/Bifrose.BWT!tr.bdr", "AVG"=>"BackDoor.Generic6.FUB", "Panda"=>"Suspicious file"}, "false"]
]
=end






