import os
import json
from collections import defaultdict
from pathlib import Path

class FingerprintAnalyzer:
    def __init__(self):
        # 使用相对路径,从当前脚本位置(tools目录)向上一级
        root_dir = os.path.dirname(os.path.dirname(__file__))
        self.pocs_path = os.path.join(root_dir, "classified_templates", "pocs")
        self.fingerprints_path = os.path.join(root_dir, "pkg", "stage", "assets", "fingerprints.json")
        self.output_pocs_path = os.path.join(root_dir, "pocs")
        
    def load_fingerprints(self):
        """加载 fingerprints.json 文件"""
        with open(self.fingerprints_path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def get_poc_categories(self):
        """获取 POC 目录下的所有分类"""
        categories = set()
        for item in os.listdir(self.pocs_path):
            if os.path.isdir(os.path.join(self.pocs_path, item)):
                categories.add(item)
        return categories
        
    def analyze_differences(self):
        """分析差异"""
        # 获取两边的分类集合
        poc_categories = self.get_poc_categories()
        fingerprints = self.load_fingerprints()
        fp_categories = set(fingerprints.keys())
        
        # 分析结果
        missing_in_fp = poc_categories - fp_categories
        missing_in_poc = fp_categories - poc_categories
        
        # 相似名称分析
        similar_names = self.find_similar_names(poc_categories, fp_categories)
        
        # 输出结果
        self.print_results(missing_in_fp, missing_in_poc, similar_names)
        
        # 生成新的指纹文件
        if missing_in_fp:
            self.generate_new_fingerprints()
        
    def find_similar_names(self, poc_cats, fp_cats):
        """查找相似的名称"""
        similar_pairs = []
        
        # 简单的相似度检查
        for poc_name in poc_cats:
            for fp_name in fp_cats:
                # 如果两个名称不完全相同但有相似之处
                if poc_name != fp_name:
                    # 检查是否包含相同的关键词
                    poc_words = set(poc_name.lower().replace('-', ' ').replace('_', ' ').split())
                    fp_words = set(fp_name.lower().replace('-', ' ').replace('_', ' ').split())
                    
                    common_words = poc_words & fp_words
                    if common_words and len(common_words) >= min(len(poc_words), len(fp_words)) / 2:
                        similar_pairs.append((poc_name, fp_name))
        
        return similar_pairs
        
    def print_results(self, missing_in_fp, missing_in_poc, similar_names):
        """打印分析结果"""
        print("=== Fingerprint Analysis Report ===\n")
        
        print("1. Missing in fingerprints.json (需要添加指纹):")
        for name in sorted(missing_in_fp):
            print(f"  - {name}")
            # 打印建议的指纹模板
            template = self.generate_fingerprint_template(name)
            print(f"    建议添加指纹:\n    {json.dumps(template, indent=4, ensure_ascii=False)}")
        print()
        
        print("2. Categories only in fingerprints.json:")
        for name in sorted(missing_in_poc):
            print(f"  - {name}")
        print()
        
        print("3. Similar names that might need consolidation:")
        for poc_name, fp_name in sorted(similar_names):
            print(f"  - POC: {poc_name} <-> Fingerprint: {fp_name}")
        print()
        
    def generate_fingerprint_template(self, category):
        """为缺失的类别生成指纹模板
        
        Args:
            category: POC目录名称
            
        Returns:
            dict: 符合fingerprints.json格式的指纹模板
        """
        template = {
            # 基础匹配规则
            "body": [
                f"(?i){category}"  # 默认使用类别名作为不区分大小写的body匹配
            ]
        }
        
        # 特殊设备类型处理
        if category.endswith('-camera'):
            template['type'] = 'ipcamera'
            manufacturer = category.replace('-camera', '')
            template['manufacturer'] = manufacturer
            
        elif category.endswith('-router'):
            template['type'] = 'router' 
            manufacturer = category.replace('-router', '')
            template['manufacturer'] = manufacturer
            
        elif category.endswith('-nas'):
            template['type'] = 'nas'
            manufacturer = category.replace('-nas', '')
            template['manufacturer'] = manufacturer
            
        # 可以继续添加其他设备类型的处理...
        
        return template
        
    def generate_new_fingerprints(self):
        """生成新的 fingerprints.json 文件"""
        # 加载现有的指纹
        current_fingerprints = self.load_fingerprints()
        
        # 获取 POC 目录下的所有分类
        poc_categories = self.get_poc_categories()
        
        # 为每个缺失的分类生成指纹
        for category in poc_categories:
            if category not in current_fingerprints:
                current_fingerprints[category] = self.generate_fingerprint_template(category)
        
        # 生成新的 fingerprints.json 文件
        output_path = os.path.join(os.path.dirname(self.fingerprints_path), 'new_fingerprints.json')
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(current_fingerprints, f, indent=2, ensure_ascii=False)
        
        # 将 POC 文件复制到上一级的 pocs 目录
        if not os.path.exists(self.output_pocs_path):
            os.makedirs(self.output_pocs_path)
        
        for category in poc_categories:
            src_dir = os.path.join(self.pocs_path, category)
            dst_dir = os.path.join(self.output_pocs_path, category)
            if os.path.exists(src_dir):
                if not os.path.exists(dst_dir):
                    os.makedirs(dst_dir)
                for file in os.listdir(src_dir):
                    src_file = os.path.join(src_dir, file)
                    dst_file = os.path.join(dst_dir, file)
                    if os.path.isfile(src_file):
                        import shutil
                        shutil.copy2(src_file, dst_file)
        
        print(f"\n新的指纹文件已生成: {output_path}")
        print(f"POC 文件已复制到: {self.output_pocs_path}")
        return output_path

def main():
    analyzer = FingerprintAnalyzer()
    analyzer.analyze_differences()

if __name__ == "__main__":
    main()
