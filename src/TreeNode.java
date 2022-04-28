import it.unisa.dia.gas.jpbc.Element;

import java.util.Arrays;
import java.util.Locale;

public class TreeNode {
    // gate用两个数(t,n)表示，n表示子节点个数, t表示门限值
    // 如果是叶子节点，则为null
    public int[] gate;
    // children表示内部节点，此字段为子节点索引列表
    // 如果是叶子节点，则为null
    public int[] children;
    // att表示属性值，全部用小写形式表示
    // 如果是内部节点，此字段null
    public String att;
    // 对应的秘密值
    public Element secretShare;

    // 用于秘密恢复，表示此节点是否可以恢复
    public boolean valid;
    //内部节点的构造方法
    public TreeNode(int[] gate, int[] children){
        this.gate = gate;
        this.children = children;
    }
    // 叶子节点的构造方法
    public TreeNode(String att){
        this.att = att.toLowerCase(Locale.ROOT);
    }
    public boolean isLeaf() {
        return this.children==null;
    }
    @Override
    public String toString() {
        if (this.isLeaf()){
            return "this is an attribute: " + att;
        }
        else {
            return "this is a gate " + Arrays.toString(this.gate) + " with children " + Arrays.toString(this.children);
        }
    }
}
