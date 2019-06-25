#!/usr/bin/env ruby

require 'rubygems'
require 'nokogiri'
require 'open-uri'
require 'pp'

$copyright = '/*
 * Microsemi Ocelot Switch driver
 *
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */'

class Field
    include Comparable
    attr_reader :name, :default, :pos, :type, :width

    def initialize n, d, p, t, w
        @name = n
        @default = d
        @pos = p
        @type = t
        @width = w
    end

    def <=>(rhs)
        x = @name <=> rhs.name
        return x if x != 0

        x = @default <=> rhs.default
        return x if x != 0

        x = @pos <=> rhs.pos
        return x if x != 0

        x = @type <=> rhs.type
        return x if x != 0

        x = @width <=> rhs.width
        return x if x != 0

        return 0
    end
end

class Reg
    include Comparable
    attr_reader :name, :addr, :repl_cnt, :repl_width, :fields

    def initialize n, a, c, w
        @name = n
        @addr = a
        @repl_cnt = c
        @repl_width = w
        @fields = {}
    end

    def add_field f
        @fields[f.name] = f
    end

    def <=>(rhs)
        x = @name <=> rhs.name
        return x if x != 0

        x = @addr <=> rhs.addr
        return x if x != 0

        x = @repl_cnt <=> rhs.repl_cnt
        return x if x != 0

        x = @repl_width <=> rhs.repl_width
        return x if x != 0

        x = @fields <=> rhs.fields
        return x if x != 0

        return 0
    end
end

class RegGroup
    include Comparable
    attr_reader :name, :regs, :base_addr, :repl_cnt, :repl_width

    def initialize n, b, c, w
        @name = n
        @base_addr = b
        @repl_cnt = c
        @repl_width = w
        @regs = {}
    end

    def add_reg r
        @regs[r.name] = r
    end

    def <=>(rhs)
        x = @name <=> rhs.name
        return x if x != 0

        x = @regs <=> rhs.regs
        return x if x != 0

        x = @base_addr <=> rhs.base_addr
        return x if x != 0

        x = @repl_cnt <=> rhs.repl_cnt
        return x if x != 0

        x = @repl_width <=> rhs.repl_width
        return x if x != 0

        return 0
    end
end

class TargetInstance
    include Comparable
    attr_reader :name, :groups, :id

    def initialize n, i
        @name = n
        @id = i
        @groups = {}
    end

    def add_group g
        @groups[g.name] = g
    end

    def <=>(rhs)
        x = @name <=> rhs.name
        return x if x != 0

        x = @groups <=> rhs.groups
        return x if x != 0

        x = @id <=> rhs.id
        return x if x != 0

        return 0
    end
end

class Target
    attr_reader :name, :id, :instances, :all_instances_matches, :multiple_instances

    def initialize n
        @name = n
        @instances = {}
        @all_instances_matches = true
        @multiple_instances = false
    end

    def add_instance i
        @instances[i.name] = i

        if @all_instances_matches
            @instances.each do |k, v|
                if v.groups != i.groups
                    @all_instances_matches = false
                    raise "no match"
                end
            end
        end

        if @instances.size > 1
            @multiple_instances = true
        end
    end

end

class Chip
    attr_reader :targets, :name

    def initialize n
        @name = n
        @targets = {}
    end

    def add_target_instance target_name, t
        if @targets[target_name].nil?
            @targets[target_name] = Target.new(target_name)
        end
        @targets[target_name].add_instance(t)
    end

    def parse_cml file
        xml = Nokogiri::XML(open(file))

        xml_chip = xml.xpath("/chip")
        xml_target_infos = xml_chip.xpath("target_info")
        xml_target_infos.each do |ti|
            xml_t = ti.xpath("target").first
            target_id = ti.xpath("./target_sim_info/@id").first.value
            target_sim_name = ti.xpath("./target_sim_info/@name").first.value
            target_name = ti.xpath("./target/@name").first.value

            next if target_name == "PCIE"
            next if target_name == "DEVCPU_GCB"
            next if target_name == "DEVCPU_ORG"
            next if target_name == "DEVCPU_PTP"
            next if target_name == "VCAP_CORE"
            next if target_name == "ICPU_CFG"
            next if target_name == "OAM_MEP"
            next if target_name == "SBA"
            next if target_name == "SFR"
            next if target_name == "SIMC"
            next if target_name == "TWI"
            next if target_name == "UART"
            if target_name == "DEVCPU_QS"
                target_name = "QS"
                target_sim_name = "QS"
            end

            t = TargetInstance.new(target_sim_name, target_id)

            xml_t.xpath("reggrp").each do |grp|
                repl_cnt = grp["repl_cnt"].to_i
                if repl_cnt == 0
                    repl_cnt = grp["repl_cnt"].to_i(16)
                end

                g = RegGroup.new grp["name"], grp["base_addr"].to_i, repl_cnt, grp["repl_width"].to_i

                grp.xpath("reg").each do |xml_r|
                    r = Reg.new xml_r["name"], xml_r["addr"].to_i, xml_r["repl_cnt"].to_i, xml_r["repl_width"]

                    xml_r.xpath("field").each do |xml_f|
                        f = Field.new xml_f["name"], xml_f["default"].to_i, xml_f["pos"].to_i, xml_f["type"], xml_f["width"].to_i
                        r.add_field(f)
                    end

                    g.add_reg(r)
                end

                t.add_group(g)
            end

            add_target_instance(target_name, t)

        end
    end
end


$regs_short_name = []

def short_names t, g, r
    case t
    when "ANA"
        case g
        when "ANA", "COMMON", "POL", "POL_MISC", "SG_ACCESS", "SG_CONFIG", "SG_STATUS"
            return "ANA_#{r}"

        when "ANA_TABLES"
            return "ANA_TABLES_#{r}"

        when "OAM_UPM_LM_CNT"
            return "ANA_OAM_UPM_LM_CNT" if r == "OAM_UPM_LM_CNT"

        when "MSTI_STATE"
            return "ANA_MSTI_STATE" if r == "MSTI_STATE"

        when "PORT"
            return "ANA_PORT_PCP_DEI_MAP" if r == "QOS_PCP_DEI_MAP_CFG"
        end


    when "DEV"
        case g
        when "PCS1G_CFG_STATUS", "PCS1G_TSTPAT_CFG_STATUS"
            return "#{r}"
        else
            return "DEV_#{r}"
        end


    when "DEVCPU_GCB"
        if g == "MIIM" and r == "MII_SCAN_LAST_RSLTS"
            return "PERF_MII_SCAN_RES"

        elsif g == "MIIM" and r == "MII_SCAN_LAST_RSLTS_VLD"
            return "PERF_MII_SCAN_RES_VLD"

        elsif g == "MIIM_READ_SCAN" and r == "MII_SCAN_RSLTS_STICKY"
            return "PERF_MII_SCAN_RES_STICKY"

        elsif g == "MIIM_SLAVE" and r == "MIIM_SLAVE_CFG"
            return "PERF_MII_SLAVE_CFG"

        else
            return "PERF_#{r}"
        end

    when "DEVCPU_PTP"
        case g
        when "PTP_CFG"
            case r
            when "CLK_ADJ_CFG", "CLK_ADJ_FRQ"
                return "PERF_PTP_#{r}"
            else
                return "PERF_#{r}"
            end

        when "PTP_PINS"
            if r == "PIN_WF_HIGH_PERIOD"
                return "PERF_PTP_PINS_WFH_PER"
            elsif r == "PIN_WF_LOW_PERIOD"
                return "PERF_PTP_PINS_WFL_PER"
            else
                return "PERF_PTP_PINS_#{r.sub(/PTP_/, "").sub(/PIN_/, "")}"
            end

        when "PTP_STATUS"
            return "PERF_PTP_STATUS_#{r.sub(/PTP_CUR_/, "")}"
        end

    when "DEVCPU_ORG"
        return "PERF_ORG_#{r}"


    when "QS"
        if r == "VTSS_DBG"
            return "QS_INH_DBG"
        else
            return "QS_#{r}"
        end

    when "VCAP_CORE"
        rr = r.gsub(/VCAP_|CORE_|TCAM_/, "")

        case g
        when "VCAP_CORE_CFG"
            return "VCAP_CORE_#{rr}"

        when "VCAP_CORE_CACHE"
            return "VCAP_CACHE_#{rr}"

        when "VCAP_CORE_MAP"
            return "VCAP_MAP_#{rr}"

        when "VCAP_CORE_STICKY"
            return "VCAP_#{rr}"

        when "VCAP_CONST"
            return "VCAP_CONST_#{rr}"

        when "TCAM_BIST"
            return "VCAP_BIST_#{rr}"
        end

    when "HSIO"
        rr = r.sub(/SERDES(\d)G/, "S\\1G")
        return "HSIO_#{rr}"

    when "ICPU_CFG"
        rr = r.sub(/_TOKEN/, "")
        return "ICPU_#{rr}"

    when "OAM_MEP"
        rr = r.gsub(/OAM_|MEP_/, "")

        case g
        when "VOE"
            return "VOE_#{rr}"
        else
            return "OAM_#{rr}"
        end

    when "QSYS", "SFR", "SYS", "REW", "TWI", "UART"
        return "#{t}_#{r}"

    end

    return "#{t}_#{g}_#{r}"
end

$chips = {}
$chips["felix"] = Chip.new "felix"
$chips["felix"].parse_cml "felix.cml"
$chips["ocelot"] = Chip.new "ocelot"
$chips["ocelot"].parse_cml "ferret_VSC_ALL.cml"

$reg_fields = []

def check_fields k, f1, f2
    if (f1.pos != f2.pos)
        n = short_names($ct, $cg, $cr)
        #puts "Field %s of %s has different positions" % [k, short_names($ct, $cg, $cr) ]
        $reg_fields << n if !($reg_fields.include? n)
    end

    #At that point, we don't care if they will be different as we will only print the common ones
    return f1
end

def merge_regs k, r1, r2
    r = Reg.new r1.name, r1.addr, r1.repl_cnt, r1.repl_width

    $cr = k

    fields = r1.fields.merge(r2.fields){|k, old, new| check_fields(k, old, new)}
    fields.each do |f_name, f|
        r.add_field(f)
    end

    return r
end

def merge_groups key, g1, g2
    g = RegGroup.new g1.name, g1.base_addr, g1.repl_cnt, g1.repl_width

    $cg = key

    if (g1.repl_cnt > 1) & (g1.repl_width != g2.repl_width)
        puts "Group %s has different sizes %d %d" % [ key, g1.repl_width, g2.repl_width ]
    end

    regs = g1.regs.merge(g2.regs){|k, old, new| merge_regs(k, old, new)}

    regs.each do |r_name, r|
        g.add_reg(r)
    end

    return g
end

def merge_targets key, t1, t2
    t = Target.new(key)
    ti = TargetInstance.new(key, 0)

    $ct = key

    t1i = t1.instances.first[1]
    t2i = t2.instances.first[1]

    groups = t1i.groups.merge(t2i.groups){|k, old, new| merge_groups(k, old, new)}

    groups.each do |g_name, g|
        ti.add_group(g)
    end

    t.add_instance(ti)

    return t
end

$targets = {}

$chips.each do |c_name, c|
    $targets = $targets.merge(c.targets){|k, old, new| merge_targets(k, old, new)}
end

file = File.new("ocelot.h",  "w+")
file.puts $copyright
file.puts ""
#Output target enum
file.puts "enum ocelot_target {"
first = 1
$targets.keys.each do |t_name|
    next if t_name == "DEV"
    next if t_name == "DEV_GMII"
    if first ==  1
        file.puts "\t%s = 1," % [ t_name ]
    else
        file.puts "\t%s," % [ t_name ]
    end
    first = 0
end
file.puts "\tTARGET_MAX,"
file.puts "};"
file.puts ""

#Output register names
file.puts "enum ocelot_reg {"
$targets.each do |t_name, t|
    next if t_name == "DEV"
    next if t_name == "DEV_GMII"
    ti = t.instances.first[1]
    first = 1
    ti.groups.each do |grp_name, grp|
        grp.regs.each do |reg_name, reg|
            n = short_names t_name, grp_name, reg_name

            raise "Name clash: #{t_name}/#{grp_name}/#{reg_name} -> '#{n}'" if $regs_short_name.include? n
            $regs_short_name << n

            if first == 1
                file.puts "\t%s = %s << TARGET_OFFSET," % [ n , t_name ]
            else
                file.puts "\t%s," % [ n ]
            end
            first = 0
        end
    end
end
file.puts "};"
file.puts ""

file.puts "enum ocelot_regfield {"
$targets.each do |t_name, t|
    ti = t.instances.first[1]
    ti.groups.each do |grp_name, grp|
        grp.regs.each do |reg_name, reg|
            n = short_names t_name, grp_name, reg_name
            if !($reg_fields.include? n)
                next
            end

            reg.fields.each do |field_name, f|
                r = n + "_" + f.name
                file.puts "\t%s," % [ r ]
            end
        end
    end
end
file.puts "\tREGFIELD_MAX"
file.puts "};"
file.puts ""

file.close

#Output common register field accessors
$targets.each do |t_name, t|
    ti = t.instances.first[1]
    file = File.new("ocelot_%s.h" % [ t_name.downcase ],  "w+")
    file.puts $copyright
    file.puts ""
    file.puts "#ifndef _MSCC_OCELOT_%s_H_" % [ t_name ]
    file.puts "#define _MSCC_OCELOT_%s_H_" % [ t_name ]
    file.puts ""
    ti.groups.each do |grp_name, grp|
        grp.regs.each do |reg_name, reg|
            n = short_names t_name, grp_name, reg_name

            blank = 0

            if t_name == "DEV" || t_name == "DEV_GMII"
                file.puts "#define %-49s 0x%x" % [n, (grp.base_addr + reg.addr) * 4 ]
                blank = 1
            end

            if grp.repl_cnt > 1
                file.puts "#define %-49s 0x%x" % [n+"_GSZ", grp.repl_width * 4]
                blank = 1
            end

            if reg.repl_cnt > 1
                file.puts "#define %-49s 0x4" % [n+"_RSZ"]
                blank = 1
            end

            if blank == 1
                file.puts ""
                blank = 0
            end

            if $reg_fields.include? n
                next
            end

            reg.fields.each do |field_name, f|
                r = n + "_" + f.name
                if f.width == 1
                    file.puts "#define %-49s BIT(%d)" %[ r, f.pos]
                    blank = 1
                else
                    next if reg.fields.count == 1 && f.width != 1
                    blank = 1
                    if f.pos == 0
                        file.puts "#define %-49s ((x) & GENMASK(%d, %d))" %[ r + "(x)" , f.pos + f.width - 1, f.pos]
                        file.puts "#define %-49s GENMASK(%d, %d)" %[ r + "_M", f.pos + f.width - 1, f.pos]
                    else
                        file.puts "#define %-49s (((x) << %d) & GENMASK(%d, %d))" %[ r + "(x)" , f.pos, f.pos + f.width - 1, f.pos]
                        file.puts "#define %-49s GENMASK(%d, %d)" %[ r + "_M", f.pos + f.width - 1, f.pos]
                        file.puts "#define %-49s (((x) & GENMASK(%d, %d)) >> %d)" %[ r + "_X(x)", f.pos + f.width - 1, f.pos, f.pos]
                    end
                end
            end

            if blank == 1
                file.puts ""
            end
        end
    end
    file.puts "#endif"
    file.close
end

def out_chip_regs chip
    file = File.new("%s.c" % [ chip.name ],  "w+")
    file.puts $copyright
    file.puts "#include \"ocelot.h\""
    file.puts ""
    chip.targets.each do |t_name, t|
        next if t_name == "DEV"
        next if t_name == "DEV_GMII"
        ti = t.instances.first[1]
        file.puts "static const u32 %s_%s_regmap[] = {" % [ chip.name, t_name.downcase ]
        ti.groups.each do |grp_name, grp|
            grp.regs.each do |reg_name, reg|
                n = short_names t_name, grp_name, reg_name
                file.puts "\tREG(%-30s 0x%06x)," % [ n+"," , (grp.base_addr + reg.addr) * 4 ]
            end
        end
        file.puts "};"
        file.puts ""
    end

    file.puts "static const u32* %s_regmap[] = {" % [ chip.name ]
    chip.targets.each do |t_name, t|
        next if t_name == "DEV"
        next if t_name == "DEV_GMII"
        ti = t.instances.first[1]
        file.puts "\t[%s] = %s_%s_regmap," % [ t_name, chip.name, t_name.downcase ]
    end
    file.puts "};"
    file.puts ""

    file.puts "static const struct reg_field %s_regfields[] = {" % [ chip.name ]
    chip.targets.each do |t_name, t|
        next if t_name == "DEV"
        next if t_name == "DEV_GMII"
        ti = t.instances.first[1]
        ti.groups.each do |grp_name, grp|
            grp.regs.each do |reg_name, reg|
                n = short_names t_name, grp_name, reg_name
                if !($reg_fields.include? n)
                    next
                end
                reg.fields.each do |field_name, f|
                    r = n + "_" + f.name
                    file.puts "\t[%s] = REG_FIELD(%s, %d, %d)," % [ r, n , f.pos, f.pos + f.width - 1 ]
                end
            end
        end
    end
    file.puts "};"
    file.puts ""

    file.puts "int %s_chip_init(struct ocelot *ocelot)
{
\tocelot->map = %s_regmap;

\treturn ocelot_regfields_init(ocelot, %s_regfields);
}" % [chip.name, chip.name, chip.name ]
    file.close
end

$chips.each do |c_name, c|
    out_chip_regs c
end
