package com.example.alcservice.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.util.Date;
import java.io.Serializable;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * <p>
 * 
 * </p>
 *
 * @author testjava
 * @since 2020-01-12
 */
@Data
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
@TableName("acl_role")
public class Role implements Serializable {

    private static final long serialVersionUID = 1L;

    //IdType.ID_WORKER_STR在mybatis plus3中已经更改为ASSIGN_ID
    @TableId(value = "id", type = IdType.ASSIGN_ID)
    private String id;

    private String roleName;

    private String roleCode;

    private String remark;

    private Boolean isDeleted;

    @TableField(fill = FieldFill.INSERT)
    private Date gmtCreate;

    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date gmtModified;


}
