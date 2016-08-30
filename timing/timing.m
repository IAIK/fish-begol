#! /bin/octave -qf

arg_list = argv();

fiatshamir = zeros(nargin - 2, 13);
bellargw   = zeros(nargin - 2, 13);

for i = 3:nargin
  data = csvread(arg_list{i});
  numr = rows(data)/2;
  fiatshamir(i - 2, :) = sum(data(1:numr,:),1)/numr;
  bellargw(i - 2, :) = sum(data(numr+1:rows(data) ,:),1)/numr;
endfor

fs_sum = zeros(nargin - 2, 3);
bg_sum = zeros(nargin - 2, 3);

fs_sum(:,1) = sum(fiatshamir(:,1:3), 2);
bg_sum(:,1) = sum(bellargw(:,1:3), 2);
fs_sum(:,2) = sum(fiatshamir(:,4:8), 2);
bg_sum(:,2) = sum(bellargw(:,4:8), 2);
fs_sum(:,3) = sum(fiatshamir(:,9:13), 2);
bg_sum(:,3) = sum(bellargw(:,9:13), 2);

fig = figure;
plot(1:nargin-2, fs_sum);
grid on;
title(strcat("LowMC Timing n=", arg_list{1}, " k=", arg_list{2}, "\n\n", "Parameters [m]-[r]"));
xlabel(" ");
xlabh = get(gca,'XLabel');
set(gca, 'xtick', 1:nargin-2);
set(gca, 'xticklabel', "");  
for i = 1:nargin-2
  text(i, 0, arg_list{i + 2}, "rotation", 60, "verticalalignment", "top", "horizontalalignment", "right");
endfor
ylabel("Time [us]");
legend("Instance Gen", "Sign", "Verify");
print(fig, strcat(arg_list{1}, "-", arg_list{2}, ".png"), "-dpng");

