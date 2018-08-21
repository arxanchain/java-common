package com.arxanfintech.common.structs;

public enum WalletType {

    ASSET(0, "Asset"), // 资产
    ORGANIZATION(2, "Organization"), // 2: 组织账户
    PERSON(3, "Person"), // 3: 通用个人账户
    INDEPENDENT(4, "Independent"), // 4: 独立个人账户(比如成人）
    DEPENDENT(5, "Dependent"), // 5：非独立个人账户(比如儿童）
    SERIALNUMBER(6, "SerialNumber"), SWCASH(11, "cash"), SWFEE(12, "fee"), SWLOAN(13, "loan"), SWINTEREST(14,
            "interest"); // ENTITY(1, "Entity"), DAPP(21, "DApp"), CHAINAPP(22, "ChainApp");

    private int index;
    private String desc;

    private WalletType(int _index, String _desc) {
        this.index = _index;
        this.desc = _desc;
    }

    public int getIndex() {
        return this.index;
    }

    public String getDesc() {
        return this.desc;
    }
}
